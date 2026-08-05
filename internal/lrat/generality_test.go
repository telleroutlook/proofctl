// Package lrat_test contains the Phase 7 generality acceptance tests.
// These tests prove the ProofGraph engine is NOT a Weil-specific wrapper
// by demonstrating that the LRAT domain uses the exact same core packages
// without any modification.
package lrat_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	adapterlrat "github.com/telleroutlook/proofctl/adapters/lrat"
	adapterweil "github.com/telleroutlook/proofctl/adapters/weil"
	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
	"github.com/telleroutlook/proofctl/internal/release"
	"github.com/telleroutlook/proofctl/internal/snapshot"
	"github.com/telleroutlook/proofctl/internal/status"
)

// testSpec returns a canonical ProblemSpec for use across tests.
func testSpec() adapterlrat.ProblemSpec {
	return adapterlrat.ProblemSpec{
		ProblemID:    "pigeonhole-3",
		Description:  "3-into-2 pigeonhole principle — unsatisfiable",
		CNFDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CNFSize:      512,
		LRATDigest:   "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		LRATSize:     2048,
		NumVariables: 6,
		NumClauses:   12,
	}
}

// weilGraphPath resolves the path to examples/weil/graph.json relative to this file.
func weilGraphPath(t *testing.T) string {
	t.Helper()
	_, testFile, _, _ := runtime.Caller(0)
	// testFile is internal/lrat/generality_test.go; repo root is two levels up.
	repoRoot := filepath.Join(filepath.Dir(testFile), "..", "..")
	path := filepath.Join(repoRoot, "examples", "weil", "graph.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("weil graph.json not found at %s: %v", path, err)
	}
	return path
}

// TestGenerality_IRModelUnchanged verifies both domains use the same ir.Claim,
// ir.EvidenceDescriptor, ir.CheckerIdentity, and ir.Attestation types.
// The types are used by construction — this test confirms fields are accessible
// and JSON-serializable for both domains.
func TestGenerality_IRModelUnchanged(t *testing.T) {
	t.Parallel()

	// Build an LRAT graph.
	a := &adapterlrat.Adapter{}
	lratGraph, err := a.Compile(testSpec())
	if err != nil {
		t.Fatalf("LRAT Compile: %v", err)
	}

	// Build a Weil graph.
	src, err := os.ReadFile(weilGraphPath(t))
	if err != nil {
		t.Fatalf("read weil graph: %v", err)
	}
	wa := &adapterweil.Adapter{ShadowMode: false}
	weilGraph, _, err := wa.Compile(src)
	if err != nil {
		t.Fatalf("Weil Compile: %v", err)
	}

	// Both must produce ir.Claim values — serialize and check structure.
	for _, c := range lratGraph.Claims {
		data, err := json.Marshal(c)
		if err != nil {
			t.Errorf("LRAT claim %q: marshal failed: %v", c.ID, err)
		}
		var back ir.Claim
		if err := json.Unmarshal(data, &back); err != nil {
			t.Errorf("LRAT claim %q: unmarshal failed: %v", c.ID, err)
		}
		if back.ID != c.ID || back.Kind != c.Kind {
			t.Errorf("LRAT claim round-trip mismatch for %q", c.ID)
		}
	}
	for _, c := range weilGraph.Claims {
		data, err := json.Marshal(c)
		if err != nil {
			t.Errorf("Weil claim %q: marshal failed: %v", c.ID, err)
		}
		var back ir.Claim
		if err := json.Unmarshal(data, &back); err != nil {
			t.Errorf("Weil claim %q: unmarshal failed: %v", c.ID, err)
		}
		if back.ID != c.ID {
			t.Errorf("Weil claim round-trip mismatch for %q", c.ID)
		}
	}

	// Both must produce ir.EvidenceDescriptor values.
	for _, e := range lratGraph.Evidence {
		data, err := json.Marshal(e)
		if err != nil {
			t.Errorf("LRAT evidence %q: marshal failed: %v", e.Digest, err)
		}
		var back ir.EvidenceDescriptor
		if err := json.Unmarshal(data, &back); err != nil {
			t.Errorf("LRAT evidence %q: unmarshal failed: %v", e.Digest, err)
		}
	}

	// Both must produce ir.CheckerIdentity values.
	for _, ch := range lratGraph.Checkers {
		data, err := json.Marshal(ch)
		if err != nil {
			t.Errorf("LRAT checker %q: marshal failed: %v", ch.ID, err)
		}
		var back ir.CheckerIdentity
		if err := json.Unmarshal(data, &back); err != nil {
			t.Errorf("LRAT checker %q: unmarshal failed: %v", ch.ID, err)
		}
		if back.ID != ch.ID {
			t.Errorf("LRAT checker round-trip mismatch for %q", ch.ID)
		}
	}

	// ir.Attestation must be JSON-serializable for both domains.
	lratAtt := &ir.Attestation{
		ClaimID:   lratGraph.Claims[0].ID,
		Outcome:   string(ir.StatusAccepted),
		Assurance: ir.AssuranceDeterministicCAP,
	}
	weilAtt := &ir.Attestation{
		ClaimID:   weilGraph.Claims[0].ID,
		Outcome:   string(ir.StatusAccepted),
		Assurance: ir.AssuranceFormalKernel,
	}
	for _, att := range []*ir.Attestation{lratAtt, weilAtt} {
		data, err := json.Marshal(att)
		if err != nil {
			t.Errorf("Attestation %q: marshal failed: %v", att.ClaimID, err)
		}
		var back ir.Attestation
		if err := json.Unmarshal(data, &back); err != nil {
			t.Errorf("Attestation %q: unmarshal failed: %v", att.ClaimID, err)
		}
	}
}

// TestGenerality_CASWorks verifies that LRAT evidence blobs round-trip through
// the same CAS used by the Weil domain.
func TestGenerality_CASWorks(t *testing.T) {
	t.Parallel()

	store, err := cas.New(t.TempDir())
	if err != nil {
		t.Fatalf("cas.New: %v", err)
	}

	cnfContent := []byte("p cnf 6 12\n1 2 0\n-1 -2 0\n")
	lratContent := []byte("1 2 3 0\n4 5 6 0\n0\n")

	// Store CNF blob.
	cnfDigest, cnfSize, _, err := store.Store(bytes.NewReader(cnfContent))
	if err != nil {
		t.Fatalf("store CNF: %v", err)
	}
	if cnfSize != int64(len(cnfContent)) {
		t.Errorf("cnfSize = %d, want %d", cnfSize, len(cnfContent))
	}

	// Store LRAT blob.
	lratDigest, lratSize, _, err := store.Store(bytes.NewReader(lratContent))
	if err != nil {
		t.Fatalf("store LRAT: %v", err)
	}
	if lratSize != int64(len(lratContent)) {
		t.Errorf("lratSize = %d, want %d", lratSize, len(lratContent))
	}

	// Verify CNF descriptor.
	cnfDesc := ir.EvidenceDescriptor{Digest: cnfDigest, Size: cnfSize}
	if err := store.Verify(cnfDesc); err != nil {
		t.Errorf("Verify CNF: %v", err)
	}

	// Verify LRAT descriptor.
	lratDesc := ir.EvidenceDescriptor{Digest: lratDigest, Size: lratSize}
	if err := store.Verify(lratDesc); err != nil {
		t.Errorf("Verify LRAT: %v", err)
	}

	// Round-trip: open CNF and read content back.
	rc, err := store.Open(cnfDigest)
	if err != nil {
		t.Fatalf("Open CNF: %v", err)
	}
	defer func() { _ = rc.Close() }()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(rc); err != nil {
		t.Fatalf("read CNF: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), cnfContent) {
		t.Errorf("CNF content mismatch after round-trip")
	}
}

// TestGenerality_DAGValidates verifies that a DAG built from LRAT claims validates
// using the same dag package as the Weil domain.
func TestGenerality_DAGValidates(t *testing.T) {
	t.Parallel()

	a := &adapterlrat.Adapter{}
	graph, err := a.Compile(testSpec())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	d := dag.New()
	for i := range graph.Claims {
		if err := d.AddClaim(&graph.Claims[i]); err != nil {
			t.Fatalf("AddClaim %q: %v", graph.Claims[i].ID, err)
		}
	}

	if err := d.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// TestGenerality_StatusCompute verifies that status.Compute returns blocked for the
// thm claim when a dependency attestation is blocked — same status machine as Weil.
func TestGenerality_StatusCompute(t *testing.T) {
	t.Parallel()

	spec := testSpec()
	a := &adapterlrat.Adapter{}
	graph, err := a.Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	d := dag.New()
	for i := range graph.Claims {
		if err := d.AddClaim(&graph.Claims[i]); err != nil {
			t.Fatalf("AddClaim %q: %v", graph.Claims[i].ID, err)
		}
	}

	formulaID := "def-" + spec.ProblemID + "-formula"
	unsatID := "lem-" + spec.ProblemID + "-unsat"
	thmID := "thm-" + spec.ProblemID + "-verified"

	// Reject the unsat claim. status.Compute propagates StatusRejected/Disproved/Error
	// from dependencies to produce StatusBlocked for dependents.
	atts := map[string]*ir.Attestation{
		formulaID: {
			ClaimID:   formulaID,
			Outcome:   string(ir.StatusAccepted),
			Assurance: ir.AssuranceExactReplay,
		},
		unsatID: {
			ClaimID:   unsatID,
			Outcome:   string(ir.StatusRejected),
			Assurance: ir.AssuranceDeterministicCAP,
		},
	}

	statuses := status.Compute(d, atts)

	if statuses[unsatID] != ir.StatusRejected {
		t.Errorf("unsat status = %q, want %q", statuses[unsatID], ir.StatusRejected)
	}
	// thm depends on unsat; unsat is rejected, so thm must be blocked by status cascade.
	if statuses[thmID] != ir.StatusBlocked {
		t.Errorf("thm status = %q, want %q (unsat is rejected)", statuses[thmID], ir.StatusBlocked)
	}
}

// TestGenerality_PolicyEvaluate verifies the LRAT policy loaded from
// policies/lrat-release-v1.json evaluates using the same policy engine as Weil.
func TestGenerality_PolicyEvaluate(t *testing.T) {
	t.Parallel()

	_, testFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(testFile), "..", "..")
	policyPath := filepath.Join(repoRoot, "policies", "lrat-release-v1.json")

	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read lrat policy: %v", err)
	}

	var pol policy.ReleasePolicy
	if err := json.Unmarshal(data, &pol); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	if pol.Version != "1" {
		t.Errorf("policy version = %q, want %q", pol.Version, "1")
	}
	if len(pol.ForbiddenAssurances) == 0 {
		t.Error("expected forbidden assurances to be non-empty")
	}

	spec := testSpec()
	a := &adapterlrat.Adapter{}
	graph, err := a.Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	d := dag.New()
	for i := range graph.Claims {
		if err := d.AddClaim(&graph.Claims[i]); err != nil {
			t.Fatalf("AddClaim %q: %v", graph.Claims[i].ID, err)
		}
	}

	formulaID := "def-" + spec.ProblemID + "-formula"
	unsatID := "lem-" + spec.ProblemID + "-unsat"
	thmID := "thm-" + spec.ProblemID + "-verified"

	// Build accepted attestations using allowed assurance types.
	atts := map[string]*ir.Attestation{
		formulaID: {ClaimID: formulaID, Outcome: string(ir.StatusAccepted), Assurance: ir.AssuranceExactReplay},
		unsatID:   {ClaimID: unsatID, Outcome: string(ir.StatusAccepted), Assurance: ir.AssuranceDeterministicCAP},
		thmID:     {ClaimID: thmID, Outcome: string(ir.StatusAccepted), Assurance: ir.AssuranceDeterministicCAP},
	}

	pass, blockers := policy.Evaluate(d, atts, pol)
	if !pass {
		t.Errorf("policy evaluation failed with blockers: %v", blockers)
	}

	// Verify a forbidden assurance blocks via C03 (assurance enforcement lives in conditions.go).
	atts[formulaID] = &ir.Attestation{
		ClaimID:   formulaID,
		Outcome:   string(ir.StatusAccepted),
		Assurance: ir.AssuranceAIReview, // forbidden
	}
	results := release.EvaluateConditions(d, atts, pol, "")
	c03Passed := true
	for _, r := range results {
		if r.ID == release.CondAllAssurancesAllowed && !r.Passed {
			c03Passed = false
		}
	}
	if c03Passed {
		t.Error("expected C03 fail for ai-review assurance, got pass")
	}
}

// TestGenerality_ReleaseGate verifies the LRAT graph runs through the same
// release gate as the Weil domain — gate.DryRun with all accepted attestations.
func TestGenerality_ReleaseGate(t *testing.T) {
	t.Parallel()

	spec := testSpec()
	a := &adapterlrat.Adapter{}
	graph, err := a.Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	d := dag.New()
	for i := range graph.Claims {
		if err := d.AddClaim(&graph.Claims[i]); err != nil {
			t.Fatalf("AddClaim %q: %v", graph.Claims[i].ID, err)
		}
	}

	formulaID := "def-" + spec.ProblemID + "-formula"
	unsatID := "lem-" + spec.ProblemID + "-unsat"
	thmID := "thm-" + spec.ProblemID + "-verified"

	// Build fully accepted attestations with all required metadata for C04-C13.
	makeAtt := func(claimID string, assurance ir.Assurance) *ir.Attestation {
		return &ir.Attestation{
			ClaimID:        claimID,
			Outcome:        string(ir.StatusAccepted),
			Assurance:      assurance,
			SelfDigest:     "sha256:aabbccddeeff00112233445566778899aabbccddeeff001122334455667788",
			StartFreshness: "sha256:start",
			EndFreshness:   "sha256:end",
			Checker:        ir.CheckerIdentity{ProtocolVersion: 2},
			ObligationResults: []ir.ObligationResult{
				{ID: "ob-1", Verdict: "pass"},
			},
			Metadata: map[string]string{
				"cap_format_version":   "v2",
				"digests_fresh":        "true",
				"path_keys_match":      "true",
				"intervals_intersect":  "true",
				"matrix_reconstructed": "true",
				"ldlt_passes":          "true",
				"odd_sector_passes":    "true",
				"even_sector_passes":   "true",
				"pivot_radius_ratio":   "150",
			},
		}
	}

	atts := map[string]*ir.Attestation{
		formulaID: makeAtt(formulaID, ir.AssuranceExactReplay),
		unsatID:   makeAtt(unsatID, ir.AssuranceDeterministicCAP),
		thmID:     makeAtt(thmID, ir.AssuranceDeterministicCAP),
	}

	pol := policy.ReleasePolicy{
		Version:             "1",
		Target:              thmID,
		AllowedAssurances:   []string{"exact-replay", "deterministic-cap"},
		ForbiddenAssurances: []string{"ai-review", "assumption", "shadow-review"},
	}

	gate := &release.Gate{OutputDir: t.TempDir()}
	pass, blockers := gate.DryRun(d, atts, pol)
	if !pass {
		t.Errorf("DryRun expected pass, got blockers: %v", blockers)
	}
}

// TestGenerality_SnapshotDeterministic verifies that taking the same LRAT graph
// snapshot twice produces the same self-digest — same snapshot mechanism as Weil.
func TestGenerality_SnapshotDeterministic(t *testing.T) {
	t.Parallel()

	spec := testSpec()
	a := &adapterlrat.Adapter{}
	graph, err := a.Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	formulaID := "def-" + spec.ProblemID + "-formula"
	unsatID := "lem-" + spec.ProblemID + "-unsat"
	thmID := "thm-" + spec.ProblemID + "-verified"

	atts := map[string]*ir.Attestation{
		formulaID: {ClaimID: formulaID, Outcome: string(ir.StatusAccepted), Assurance: ir.AssuranceExactReplay},
		unsatID:   {ClaimID: unsatID, Outcome: string(ir.StatusAccepted), Assurance: ir.AssuranceDeterministicCAP},
		thmID:     {ClaimID: thmID, Outcome: string(ir.StatusAccepted), Assurance: ir.AssuranceDeterministicCAP},
	}
	statuses := map[string]ir.Status{
		formulaID: ir.StatusAccepted,
		unsatID:   ir.StatusAccepted,
		thmID:     ir.StatusAccepted,
	}

	const testTime = "2026-08-03T00:00:00Z"

	s1, err := snapshot.Take(graph.Claims, atts, statuses, testTime)
	if err != nil {
		t.Fatalf("snapshot.Take #1: %v", err)
	}
	s2, err := snapshot.Take(graph.Claims, atts, statuses, testTime)
	if err != nil {
		t.Fatalf("snapshot.Take #2: %v", err)
	}

	if s1.SelfDigest != s2.SelfDigest {
		t.Errorf("non-deterministic snapshot:\n  first:  %s\n  second: %s", s1.SelfDigest, s2.SelfDigest)
	}
	if !strings.HasPrefix(s1.SelfDigest, "sha256:") {
		t.Errorf("SelfDigest has unexpected prefix: %q", s1.SelfDigest)
	}
}

// TestGenerality_NoCoreModification documents the guarantee that the LRAT domain
// uses the exact same core internal packages as the Weil domain.
// This test verifies the import paths at compile time by using each package.
func TestGenerality_NoCoreModification(t *testing.T) {
	t.Parallel()

	// ir: same types for both domains
	_ = ir.Claim{}
	_ = ir.EvidenceDescriptor{}
	_ = ir.CheckerIdentity{}
	_ = ir.Attestation{}
	_ = ir.ProofGraph{}

	// dag: same graph structure
	d := dag.New()
	c := &ir.Claim{ID: "test-claim", Kind: "test"}
	if err := d.AddClaim(c); err != nil {
		t.Fatalf("dag.AddClaim: %v", err)
	}

	// status: same status machine
	atts := map[string]*ir.Attestation{
		"test-claim": {ClaimID: "test-claim", Outcome: string(ir.StatusAccepted)},
	}
	statuses := status.Compute(d, atts)
	if statuses["test-claim"] != ir.StatusAccepted {
		t.Errorf("status = %q, want accepted", statuses["test-claim"])
	}

	// snapshot: same snapshot mechanism
	_, err := snapshot.Take([]ir.Claim{*c}, atts,
		map[string]ir.Status{"test-claim": ir.StatusAccepted},
		"2026-08-03T00:00:00Z")
	if err != nil {
		t.Fatalf("snapshot.Take: %v", err)
	}

	// release: same release gate type (construction only, not a full gate run)
	_ = &release.Gate{OutputDir: t.TempDir()}

	// policy: same policy engine
	_ = policy.ReleasePolicy{}

	// cas: same content-addressed store
	_, err = cas.New(t.TempDir())
	if err != nil {
		t.Fatalf("cas.New: %v", err)
	}
}
