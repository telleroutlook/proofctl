package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
	"github.com/telleroutlook/proofctl/internal/release"
)

// secBuildGraph builds a DAG with the given claim IDs (no deps).
func secBuildGraph(t *testing.T, ids ...string) *dag.DAG {
	t.Helper()
	d := dag.New()
	for _, id := range ids {
		if err := d.AddClaim(&ir.Claim{ID: id, Kind: "test"}); err != nil {
			t.Fatalf("AddClaim(%q): %v", id, err)
		}
	}
	return d
}

// secAtt returns an accepted Attestation with the given assurance.
func secAtt(claimID string, assurance ir.Assurance) *ir.Attestation {
	return &ir.Attestation{
		ClaimID:   claimID,
		Outcome:   string(ir.StatusAccepted),
		Assurance: assurance,
	}
}

// TestAdversarial_MissingAttestation creates a graph with 3 claims, attests only 2,
// and verifies that Release writes STATUS.json with "released": false.
func TestAdversarial_MissingAttestation(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &release.Gate{OutputDir: outDir}

	graph := secBuildGraph(t, "c1", "c2", "c3")
	atts := map[string]*ir.Attestation{
		"c1": secAtt("c1", ir.AssuranceFormalKernel),
		"c2": secAtt("c2", ir.AssuranceFormalKernel),
		// c3 is intentionally not attested.
	}
	pol := policy.ReleasePolicy{
		Version:        "1",
		Target:         "test-target",
		RequiredClaims: []string{"c1", "c2", "c3"},
	}

	pass, blockers, err := g.Release(graph, atts, pol, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if pass {
		t.Error("expected fail when c3 has no attestation, got pass")
	}
	if len(blockers) == 0 {
		t.Error("expected non-empty blockers")
	}

	data, err := os.ReadFile(filepath.Join(outDir, release.StatusFile))
	if err != nil {
		t.Fatalf("read STATUS.json: %v", err)
	}
	var rs release.ReleaseStatus
	if err := json.Unmarshal(data, &rs); err != nil {
		t.Fatalf("unmarshal STATUS.json: %v", err)
	}
	if rs.Released {
		t.Error("STATUS.json must have released=false when attestation is missing")
	}
}

// TestAdversarial_ForbiddenAssuranceInClosure creates a graph where one dep uses
// "ai-review" assurance and verifies that Release is blocked.
func TestAdversarial_ForbiddenAssuranceInClosure(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &release.Gate{OutputDir: outDir}

	graph := secBuildGraph(t, "root", "tip")
	atts := map[string]*ir.Attestation{
		"root": secAtt("root", ir.AssuranceAIReview), // forbidden
		"tip":  secAtt("tip", ir.AssuranceFormalKernel),
	}
	pol := policy.ReleasePolicy{
		Version:             "1",
		Target:              "test-target",
		RequiredClaims:      []string{"root", "tip"},
		ForbiddenAssurances: []string{string(ir.AssuranceAIReview)},
	}

	pass, blockers, err := g.Release(graph, atts, pol, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if pass {
		t.Error("expected fail for forbidden assurance in closure, got pass")
	}
	if len(blockers) == 0 {
		t.Error("expected non-empty blockers")
	}
}

// TestAdversarial_DryRunMatchesRelease verifies that DryRun and Release return
// identical pass/fail/blockers for the same input (they share the same check function).
func TestAdversarial_DryRunMatchesRelease(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &release.Gate{OutputDir: outDir}

	graph := secBuildGraph(t, "c1", "c2")
	atts := map[string]*ir.Attestation{
		"c1": secAtt("c1", ir.AssuranceFormalKernel),
		"c2": {
			ClaimID:   "c2",
			Outcome:   string(ir.StatusRejected),
			Assurance: ir.AssuranceFormalKernel,
		},
	}
	pol := policy.ReleasePolicy{
		Version:        "1",
		Target:         "test-target",
		RequiredClaims: []string{"c1", "c2"},
	}

	dryPass, dryBlockers := g.DryRun(graph, atts, pol)
	relPass, relBlockers, err := g.Release(graph, atts, pol, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}

	if dryPass != relPass {
		t.Errorf("DryRun pass=%v, Release pass=%v — must match", dryPass, relPass)
	}
	if len(dryBlockers) != len(relBlockers) {
		t.Errorf("DryRun blockers=%d, Release blockers=%d — must match",
			len(dryBlockers), len(relBlockers))
	}
}

// TestAdversarial_ConcurrentRelease calls Release simultaneously from 5 goroutines
// and verifies all produce valid JSON, "released" is consistent, and no temp files
// remain after all are done.
func TestAdversarial_ConcurrentRelease(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &release.Gate{OutputDir: outDir}

	graph := secBuildGraph(t, "c1", "c2")
	atts := map[string]*ir.Attestation{
		"c1": secAtt("c1", ir.AssuranceFormalKernel),
		"c2": secAtt("c2", ir.AssuranceFormalKernel),
	}
	pol := policy.ReleasePolicy{
		Version:        "1",
		Target:         "concurrent-target",
		RequiredClaims: []string{"c1", "c2"},
	}

	const goroutines = 5
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := g.Release(graph, atts, pol, nil)
			if err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("goroutine Release error: %v", err)
	}

	// STATUS.json must exist and be valid.
	data, err := os.ReadFile(filepath.Join(outDir, release.StatusFile))
	if err != nil {
		t.Fatalf("read STATUS.json after concurrent releases: %v", err)
	}
	var rs release.ReleaseStatus
	if err := json.Unmarshal(data, &rs); err != nil {
		t.Fatalf("STATUS.json is invalid JSON after concurrent releases: %v", err)
	}

	// No temp files must remain (STATUS.json and release-snapshot.json are expected outputs).
	expectedFiles := map[string]bool{
		release.StatusFile:   true,
		release.SnapshotFile: true,
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if !expectedFiles[e.Name()] {
			t.Errorf("unexpected leftover file after concurrent releases: %q", e.Name())
		}
	}
}

// TestAdversarial_ForgingV2OutcomeFieldCannotBypassC01 verifies that a v2 attestation
// whose "outcome" field was hand-crafted to "accepted" (but has no passing obligation
// results) is rejected by C01 — the forged Outcome field must not be trusted.
func TestAdversarial_ForgingV2OutcomeFieldCannotBypassC01(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &release.Gate{OutputDir: outDir}

	graph := secBuildGraph(t, "c1")

	// Attacker writes a v2 attestation with "outcome":"accepted" but no ObligationResults.
	// This is the attack described in the evaluation report (Milestone 37 P0).
	forgedAtt := &ir.Attestation{
		ClaimID: "c1",
		Checker: ir.CheckerIdentity{ProtocolVersion: 2},
		Outcome: string(ir.StatusAccepted), // forged — must NOT be trusted by C01
		// ObligationResults intentionally empty — no checker ever ran
	}
	atts := map[string]*ir.Attestation{"c1": forgedAtt}
	pol := policy.ReleasePolicy{
		Version:        "2",
		Target:         "c1",
		RequiredClaims: []string{"c1"},
	}

	pass, blockers, err := g.Release(graph, atts, pol, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if pass {
		t.Error("forged v2 Outcome='accepted' with no ObligationResults must NOT pass release")
	}
	if len(blockers) == 0 {
		t.Error("expected at least one blocker for forged attestation")
	}
	// Verify STATUS.json also records released=false.
	data, readErr := os.ReadFile(filepath.Join(outDir, release.StatusFile))
	if readErr != nil {
		t.Fatalf("read STATUS.json: %v", readErr)
	}
	var rs release.ReleaseStatus
	if jsonErr := json.Unmarshal(data, &rs); jsonErr != nil {
		t.Fatalf("unmarshal STATUS.json: %v", jsonErr)
	}
	if rs.Released {
		t.Error("STATUS.json must have released=false for forged attestation")
	}
}

// TestAdversarial_ForgingV2OutcomeWithFailObligations verifies that a v2 attestation
// with one failing obligation is also rejected even if Outcome is set to "accepted".
func TestAdversarial_ForgingV2OutcomeWithFailObligations(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &release.Gate{OutputDir: outDir}

	graph := secBuildGraph(t, "c1")

	forgedAtt := &ir.Attestation{
		ClaimID: "c1",
		Checker: ir.CheckerIdentity{ProtocolVersion: 2},
		Outcome: string(ir.StatusAccepted), // forged
		ObligationResults: []ir.ObligationResult{
			{ID: "ob-pass", Verdict: "pass"},
			{ID: "ob-fail", Verdict: "fail"}, // one failure — must block
		},
	}
	atts := map[string]*ir.Attestation{"c1": forgedAtt}
	pol := policy.ReleasePolicy{Version: "2", Target: "c1", RequiredClaims: []string{"c1"}}

	pass, _, err := g.Release(graph, atts, pol, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if pass {
		t.Error("v2 attestation with a failing obligation must NOT pass release")
	}
}

// TestAdversarial_V2AllPassObligationsAreAccepted verifies the positive case:
// a v2 attestation with all obligations passing is correctly accepted.
func TestAdversarial_V2AllPassObligationsAreAccepted(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &release.Gate{OutputDir: outDir}

	graph := secBuildGraph(t, "c1")

	goodAtt := &ir.Attestation{
		ClaimID:        "c1",
		Checker:        ir.CheckerIdentity{ProtocolVersion: 2},
		Outcome:        string(ir.StatusAccepted),
		SelfDigest:     "sha256:abc",
		StartFreshness: "sha256:s",
		EndFreshness:   "sha256:e",
		ObligationResults: []ir.ObligationResult{
			{ID: "ob-1", Verdict: "pass"},
			{ID: "ob-2", Verdict: "pass"},
		},
	}
	atts := map[string]*ir.Attestation{"c1": goodAtt}
	pol := policy.ReleasePolicy{
		Version:        "2",
		Target:         "c1",
		RequiredClaims: []string{"c1"},
		AllowedAssurances: []string{
			"deterministic-cap", "formal-kernel", "exact-replay",
			"reproducible-computation", "independent-review",
		},
	}

	pass, blockers, err := g.Release(graph, atts, pol, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !pass {
		t.Errorf("v2 attestation with all-pass obligations must succeed; blockers: %v", blockers)
	}
}
