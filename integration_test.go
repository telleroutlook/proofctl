//go:build integration

package proofctl_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/telleroutlook/proofctl/internal/compile"
	"github.com/telleroutlook/proofctl/internal/config"
	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
	"github.com/telleroutlook/proofctl/internal/release"
	"github.com/telleroutlook/proofctl/internal/snapshot"
	"github.com/telleroutlook/proofctl/internal/status"
	"github.com/telleroutlook/proofctl/internal/weil"
)

const exampleGraphPath = "examples/weil/graph.json"

// setupWeilShadow initializes a temp project, compiles examples/weil/graph.json
// with the weil adapter in shadow mode, and returns the populated DAG,
// attestation map, and project root.
func setupWeilShadow(t *testing.T) (root string, g *dag.DAG, atts map[string]*ir.Attestation) {
	t.Helper()

	dir := t.TempDir()

	// Initialize project structure.
	if err := config.Init(dir, ""); err != nil {
		t.Fatalf("config.Init: %v", err)
	}

	// Copy example graph into temp dir as the source.
	src, err := os.ReadFile(exampleGraphPath)
	if err != nil {
		t.Fatalf("read example graph: %v", err)
	}
	srcPath := filepath.Join(dir, "graph.json")
	if err := os.WriteFile(srcPath, src, 0o644); err != nil {
		t.Fatalf("write source graph: %v", err)
	}

	// Compile with weil adapter (shadow mode).
	pg, shadowAtts, err := compileWeilAdapter(src)
	if err != nil {
		t.Fatalf("compileWeilAdapter: %v", err)
	}

	// Write graph.json to .proofctl/.
	graphOut := filepath.Join(dir, config.DirName, config.GraphFile)
	if err := writeJSONFile(graphOut, pg); err != nil {
		t.Fatalf("write graph.json: %v", err)
	}

	// Write shadow attestations.
	attestDir := filepath.Join(dir, config.DirName, config.AttestDir)
	for claimID, att := range shadowAtts {
		attPath := filepath.Join(attestDir, claimID+".json")
		if err := writeJSONFile(attPath, att); err != nil {
			t.Fatalf("write attestation %s: %v", claimID, err)
		}
	}

	// Build DAG from compiled graph.
	g = dag.New()
	for i := range pg.Claims {
		if err := g.AddClaim(&pg.Claims[i]); err != nil {
			t.Fatalf("AddClaim(%q): %v", pg.Claims[i].ID, err)
		}
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("dag.Validate: %v", err)
	}

	return dir, g, shadowAtts
}

// compileWeilAdapter mimics the weil adapter compile path used by cmdCompile.
func compileWeilAdapter(src []byte) (*ir.ProofGraph, map[string]*ir.Attestation, error) {
	pg, err := compile.Compile(src, compile.FormatJSON)
	if err != nil {
		return nil, nil, err
	}
	defects := weil.DefectsByClaimID()
	atts := make(map[string]*ir.Attestation, len(pg.Claims))
	for i := range pg.Claims {
		c := &pg.Claims[i]
		if defect, ok := defects[c.ID]; ok {
			atts[c.ID] = weil.BuildShadowAttestation(c, defect)
		} else {
			atts[c.ID] = weil.BuildOpenAttestation(c)
		}
	}
	return pg, atts, nil
}

// writeJSONFile atomically writes v as indented JSON to path.
func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

// TestWeilShadowIntegration runs the full init → compile → status → release pipeline.
func TestWeilShadowIntegration(t *testing.T) {
	t.Parallel()

	_, g, atts := setupWeilShadow(t)

	// Step 3: Compute statuses.
	statuses := status.Compute(g, atts)

	// Assert thm-main-radius-030 is blocked.
	if s := statuses["thm-main-radius-030"]; s != ir.StatusBlocked {
		t.Errorf("thm-main-radius-030: expected blocked, got %q", s)
	}

	// Assert lem-d4-kernel-bound is blocked.
	if s := statuses["lem-d4-kernel-bound"]; s != ir.StatusBlocked {
		t.Errorf("lem-d4-kernel-bound: expected blocked, got %q", s)
	}

	// Assert lem-d4-kernel-bound has a block reason containing "D4".
	if att, ok := atts["lem-d4-kernel-bound"]; !ok || att.BlockReason == "" {
		t.Error("lem-d4-kernel-bound: expected non-empty block reason")
	} else if !contains(att.BlockReason, "D4") {
		t.Errorf("lem-d4-kernel-bound: block reason %q does not contain D4", att.BlockReason)
	}

	// Assert lem-ab-intersection is blocked with reason containing "D8".
	if s := statuses["lem-ab-intersection"]; s != ir.StatusBlocked {
		t.Errorf("lem-ab-intersection: expected blocked, got %q", s)
	}
	if att, ok := atts["lem-ab-intersection"]; !ok || att.BlockReason == "" {
		t.Error("lem-ab-intersection: expected non-empty block reason")
	} else if !contains(att.BlockReason, "D8") {
		t.Errorf("lem-ab-intersection: block reason %q does not contain D8", att.BlockReason)
	}

	// Assert no claim is accepted.
	for id, s := range statuses {
		if s == ir.StatusAccepted {
			t.Errorf("claim %q should not be accepted in shadow mode", id)
		}
	}

	// Step 4: Run release dry-run with weil-release-v1.json policy.
	polData, err := os.ReadFile("policies/weil-release-v1.json")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	var pol policy.ReleasePolicy
	if err := json.Unmarshal(polData, &pol); err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	gate := &release.Gate{OutputDir: t.TempDir()}
	pass, blockers := gate.DryRun(g, atts, pol)

	// Assert: pass=false.
	if pass {
		t.Error("release DryRun: expected blocked, got pass")
	}

	// Assert: blockers is non-empty.
	if len(blockers) == 0 {
		t.Error("release DryRun: expected non-empty blockers")
	}

	// Assert: release_target stays null (no STATUS.json written).
	for _, b := range blockers {
		if contains(b, "release_target") {
			t.Errorf("unexpected release_target in blocker: %q", b)
		}
	}
}

// TestColdReplay verifies that running compile twice produces identical output.
func TestColdReplay(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile(exampleGraphPath)
	if err != nil {
		t.Fatalf("read example graph: %v", err)
	}

	// Run 1.
	pg1, atts1, err := compileWeilAdapter(src)
	if err != nil {
		t.Fatalf("run 1 compileWeilAdapter: %v", err)
	}

	// Run 2.
	pg2, atts2, err := compileWeilAdapter(src)
	if err != nil {
		t.Fatalf("run 2 compileWeilAdapter: %v", err)
	}

	// Assert byte-identical graph.json output.
	graph1, err := json.MarshalIndent(pg1, "", "  ")
	if err != nil {
		t.Fatalf("marshal pg1: %v", err)
	}
	graph2, err := json.MarshalIndent(pg2, "", "  ")
	if err != nil {
		t.Fatalf("marshal pg2: %v", err)
	}
	if !bytes.Equal(graph1, graph2) {
		t.Error("cold replay: graph.json output differs between runs")
	}

	// Assert identical attestation content for each claim.
	for claimID, att1 := range atts1 {
		att2, ok := atts2[claimID]
		if !ok {
			t.Errorf("cold replay: attestation for %q missing in run 2", claimID)
			continue
		}
		b1, err := json.MarshalIndent(att1, "", "  ")
		if err != nil {
			t.Fatalf("marshal att1[%s]: %v", claimID, err)
		}
		b2, err := json.MarshalIndent(att2, "", "  ")
		if err != nil {
			t.Fatalf("marshal att2[%s]: %v", claimID, err)
		}
		if !bytes.Equal(b1, b2) {
			t.Errorf("cold replay: attestation for %q differs between runs", claimID)
		}
	}
	if len(atts1) != len(atts2) {
		t.Errorf("cold replay: attestation count differs: run1=%d run2=%d", len(atts1), len(atts2))
	}
}

// TestShadowAssuranceForbidden verifies that shadow attestations cannot satisfy release policy.
func TestShadowAssuranceForbidden(t *testing.T) {
	t.Parallel()

	// Build a minimal graph with one claim attested as shadow-review.
	g := dag.New()
	c := &ir.Claim{
		ID:   "test-claim",
		Kind: "theorem",
		Statement: ir.Statement{
			Text:   "test statement",
			Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	if err := g.AddClaim(c); err != nil {
		t.Fatalf("AddClaim: %v", err)
	}

	atts := map[string]*ir.Attestation{
		"test-claim": {
			ClaimID:     "test-claim",
			Outcome:     string(ir.StatusBlocked),
			Assurance:   weil.ShadowAssurance,
			BlockReason: "test: shadow mode only",
		},
	}

	// Use a policy that explicitly forbids shadow-review.
	pol := policy.ReleasePolicy{
		Version:             "1",
		Target:              "test-claim",
		ForbiddenAssurances: []string{string(weil.ShadowAssurance)},
	}

	// C03 (assurance enforcement) must block shadow-review.
	results := release.EvaluateConditions(g, atts, pol, "")
	c03Blocked := false
	for _, r := range results {
		if r.ID == release.CondAllAssurancesAllowed && !r.Passed {
			c03Blocked = true
			if !contains(r.Blocker, "shadow-review") {
				t.Errorf("C03 blocker does not mention shadow-review: %q", r.Blocker)
			}
		}
	}
	if !c03Blocked {
		t.Error("shadow assurance: expected C03 to block shadow-review, got pass")
	}
}

// contains reports whether substr is found in s.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		indexString(s, substr) >= 0)
}

// indexString returns the index of the first occurrence of substr in s, or -1.
func indexString(s, substr string) int {
	n := len(substr)
	if n == 0 {
		return 0
	}
	for i := 0; i <= len(s)-n; i++ {
		if s[i:i+n] == substr {
			return i
		}
	}
	return -1
}

// claimsFromDAG converts []*ir.Claim to []ir.Claim for snapshot.Take.
func claimsFromDAG(g *dag.DAG) []ir.Claim {
	ptrs := g.Claims()
	out := make([]ir.Claim, len(ptrs))
	for i, c := range ptrs {
		out[i] = *c
	}
	return out
}

// runWeilShadowPipeline runs the full init→compile→status→release pipeline
// in an isolated temp dir and returns the graph, attestations, statuses,
// and the DryRun result.
func runWeilShadowPipeline(t *testing.T) (
	g *dag.DAG,
	atts map[string]*ir.Attestation,
	statuses map[string]ir.Status,
	pass bool,
	blockers []string,
	pol policy.ReleasePolicy,
) {
	t.Helper()
	_, g, atts = setupWeilShadow(t)
	statuses = status.Compute(g, atts)

	polData, err := os.ReadFile("policies/weil-release-v1.json")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if err := json.Unmarshal(polData, &pol); err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	gate := &release.Gate{OutputDir: t.TempDir()}
	pass, blockers = gate.DryRun(g, atts, pol)
	return
}

// TestPhase5ColdReplay runs the full pipeline twice in separate temp dirs
// and asserts deterministic output across both runs.
func TestPhase5ColdReplay(t *testing.T) {
	t.Parallel()

	const fixedTimestamp = "2026-01-01T00:00:00Z"

	src, err := os.ReadFile(exampleGraphPath)
	if err != nil {
		t.Fatalf("read example graph: %v", err)
	}

	// --- Run 1 ---
	dir1 := t.TempDir()
	if err := config.Init(dir1, ""); err != nil {
		t.Fatalf("run1 config.Init: %v", err)
	}
	pg1, atts1, err := compileWeilAdapter(src)
	if err != nil {
		t.Fatalf("run1 compileWeilAdapter: %v", err)
	}
	graphOut1 := filepath.Join(dir1, config.DirName, config.GraphFile)
	if err := writeJSONFile(graphOut1, pg1); err != nil {
		t.Fatalf("run1 write graph.json: %v", err)
	}

	// --- Run 2 ---
	dir2 := t.TempDir()
	if err := config.Init(dir2, ""); err != nil {
		t.Fatalf("run2 config.Init: %v", err)
	}
	pg2, atts2, err := compileWeilAdapter(src)
	if err != nil {
		t.Fatalf("run2 compileWeilAdapter: %v", err)
	}
	graphOut2 := filepath.Join(dir2, config.DirName, config.GraphFile)
	if err := writeJSONFile(graphOut2, pg2); err != nil {
		t.Fatalf("run2 write graph.json: %v", err)
	}

	// 1. Assert graph.json is byte-identical between the two runs.
	graph1Bytes, err := json.MarshalIndent(pg1, "", "  ")
	if err != nil {
		t.Fatalf("marshal pg1: %v", err)
	}
	graph2Bytes, err := json.MarshalIndent(pg2, "", "  ")
	if err != nil {
		t.Fatalf("marshal pg2: %v", err)
	}
	if !bytes.Equal(graph1Bytes, graph2Bytes) {
		t.Error("phase5 cold replay: graph.json output differs between runs")
	}

	// 2. Assert every attestation file is byte-identical.
	for claimID, att1 := range atts1 {
		att2, ok := atts2[claimID]
		if !ok {
			t.Errorf("phase5 cold replay: attestation %q missing in run 2", claimID)
			continue
		}
		b1, _ := json.MarshalIndent(att1, "", "  ")
		b2, _ := json.MarshalIndent(att2, "", "  ")
		if !bytes.Equal(b1, b2) {
			t.Errorf("phase5 cold replay: attestation %q differs between runs", claimID)
		}
	}
	if len(atts1) != len(atts2) {
		t.Errorf("phase5 cold replay: attestation count differs: run1=%d run2=%d", len(atts1), len(atts2))
	}

	// Build DAGs for status and release checks.
	g1 := dag.New()
	for i := range pg1.Claims {
		if err := g1.AddClaim(&pg1.Claims[i]); err != nil {
			t.Fatalf("run1 AddClaim: %v", err)
		}
	}
	if err := g1.Validate(); err != nil {
		t.Fatalf("run1 Validate: %v", err)
	}

	g2 := dag.New()
	for i := range pg2.Claims {
		if err := g2.AddClaim(&pg2.Claims[i]); err != nil {
			t.Fatalf("run2 AddClaim: %v", err)
		}
	}
	if err := g2.Validate(); err != nil {
		t.Fatalf("run2 Validate: %v", err)
	}

	// 3. Assert status output is identical.
	statuses1 := status.Compute(g1, atts1)
	statuses2 := status.Compute(g2, atts2)

	if len(statuses1) != len(statuses2) {
		t.Errorf("phase5 cold replay: status count differs: run1=%d run2=%d", len(statuses1), len(statuses2))
	}
	for id, s1 := range statuses1 {
		s2, ok := statuses2[id]
		if !ok {
			t.Errorf("phase5 cold replay: status for %q missing in run 2", id)
			continue
		}
		if s1 != s2 {
			t.Errorf("phase5 cold replay: status for %q differs: run1=%q run2=%q", id, s1, s2)
		}
	}

	// 4. Assert release DryRun result is identical (pass=false, same blockers set).
	// Compare via EvaluateConditions for structured, deterministic comparison of
	// which condition IDs fail — raw DryRun blocker strings contain map-iterated claim
	// lists whose ordering is non-deterministic across runs.
	polData, err := os.ReadFile("policies/weil-release-v1.json")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	var pol policy.ReleasePolicy
	if err := json.Unmarshal(polData, &pol); err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	gate1 := &release.Gate{OutputDir: t.TempDir()}
	pass1, _ := gate1.DryRun(g1, atts1, pol)

	gate2 := &release.Gate{OutputDir: t.TempDir()}
	pass2, _ := gate2.DryRun(g2, atts2, pol)

	if pass1 != pass2 {
		t.Errorf("phase5 cold replay: DryRun pass differs: run1=%v run2=%v", pass1, pass2)
	}
	if pass1 {
		t.Error("phase5 cold replay: DryRun expected blocked in shadow mode, got pass")
	}

	// Compare failing condition IDs (which are deterministic, unlike claim-list strings).
	conds1 := release.EvaluateConditions(g1, atts1, pol, "")
	conds2 := release.EvaluateConditions(g2, atts2, pol, "")

	var failedIDs1, failedIDs2 []string
	for _, c := range conds1 {
		if !c.Passed {
			failedIDs1 = append(failedIDs1, string(c.ID))
		}
	}
	for _, c := range conds2 {
		if !c.Passed {
			failedIDs2 = append(failedIDs2, string(c.ID))
		}
	}
	sort.Strings(failedIDs1)
	sort.Strings(failedIDs2)

	failedSetsEqual := func() bool {
		if len(failedIDs1) != len(failedIDs2) {
			return false
		}
		for i := range failedIDs1 {
			if failedIDs1[i] != failedIDs2[i] {
				return false
			}
		}
		return true
	}()
	if !failedSetsEqual {
		t.Errorf("phase5 cold replay: failing condition sets differ:\n  run1=%v\n  run2=%v",
			failedIDs1, failedIDs2)
	}

	// 5. Assert snapshot self-digest is identical between runs (fixed timestamp).
	snap1, err := snapshot.Take(claimsFromDAG(g1), atts1, statuses1, fixedTimestamp)
	if err != nil {
		t.Fatalf("run1 snapshot.Take: %v", err)
	}
	snap2, err := snapshot.Take(claimsFromDAG(g2), atts2, statuses2, fixedTimestamp)
	if err != nil {
		t.Fatalf("run2 snapshot.Take: %v", err)
	}

	if snap1.SelfDigest != snap2.SelfDigest {
		t.Errorf("phase5 cold replay: snapshot self-digest differs:\n  run1=%s\n  run2=%s",
			snap1.SelfDigest, snap2.SelfDigest)
	}
}

// TestPhase5ConditionResults evaluates the 13 structured conditions against
// the Weil shadow integration and asserts the expected pass/fail pattern.
func TestPhase5ConditionResults(t *testing.T) {
	t.Parallel()

	_, g, atts := setupWeilShadow(t)

	polData, err := os.ReadFile("policies/weil-release-v1.json")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	var pol policy.ReleasePolicy
	if err := json.Unmarshal(polData, &pol); err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	// Evaluate all 13 conditions.
	conditions := release.EvaluateConditions(g, atts, pol, "")

	// Build a map for easy lookup.
	condMap := make(map[release.ConditionID]release.ConditionResult, len(conditions))
	for _, c := range conditions {
		condMap[c.ID] = c
	}

	// C01 must fail: no claims are accepted in shadow mode.
	if c01, ok := condMap[release.CondGlobalStatusAccepted]; !ok {
		t.Error("C01 result missing")
	} else if c01.Passed {
		t.Error("C01 expected FAIL (no accepted claims in shadow mode), got PASS")
	}

	// C02 must pass: shadow-review is not "assumption" assurance.
	if c02, ok := condMap[release.CondAssumptionFootprintEmpty]; !ok {
		t.Error("C02 result missing")
	} else if !c02.Passed {
		t.Errorf("C02 expected PASS (no assumption assurance), got FAIL: %s", c02.Blocker)
	}

	// C03 must fail: shadow-review is forbidden by the release policy.
	if c03, ok := condMap[release.CondAllAssurancesAllowed]; !ok {
		t.Error("C03 result missing")
	} else if c03.Passed {
		t.Error("C03 expected FAIL (shadow-review is forbidden), got PASS")
	} else if !contains(c03.Blocker, "shadow-review") && !contains(c03.Blocker, "forbidden") {
		t.Errorf("C03 blocker does not mention shadow-review or forbidden: %s", c03.Blocker)
	}

	// C13 must fail: shadow attestations have no freshness/replay data.
	if c13, ok := condMap[release.CondReplayConsistency]; !ok {
		t.Error("C13 result missing")
	} else if c13.Passed {
		t.Error("C13 expected FAIL (no freshness in shadow attestations), got PASS")
	}

	// AllPassed must return false.
	if release.AllPassed(conditions) {
		t.Error("AllPassed expected false, got true")
	}

	// Blockers must be non-empty.
	blockerList := release.Blockers(conditions)
	if len(blockerList) == 0 {
		t.Error("Blockers() expected non-empty list, got empty")
	}
}
