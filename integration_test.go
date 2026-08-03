//go:build integration

package proofctl_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/telleroutlook/proofctl/internal/compile"
	"github.com/telleroutlook/proofctl/internal/config"
	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
	"github.com/telleroutlook/proofctl/internal/release"
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
	if err := config.Init(dir); err != nil {
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

	// Assert: certified_radius stays null (no STATUS.json written).
	for _, b := range blockers {
		if contains(b, "certified_radius") {
			t.Errorf("unexpected certified_radius in blocker: %q", b)
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

	// Load weil-release-v1.json policy.
	polData, err := os.ReadFile("policies/weil-release-v1.json")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	var pol policy.ReleasePolicy
	if err := json.Unmarshal(polData, &pol); err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	// Evaluate policy: shadow-review must be blocked.
	pass, blockers := policy.Evaluate(g, atts, pol)
	if pass {
		t.Error("shadow assurance: expected policy to block, got pass")
	}
	if len(blockers) == 0 {
		t.Error("shadow assurance: expected non-empty blockers for shadow-review")
	}

	// Verify at least one blocker mentions shadow-review.
	found := false
	for _, b := range blockers {
		if contains(b, "shadow-review") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("shadow assurance: no blocker mentions shadow-review; blockers: %v", blockers)
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
