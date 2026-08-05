package release_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
	"github.com/telleroutlook/proofctl/internal/release"
	"github.com/telleroutlook/proofctl/internal/signing"
)

// coverBuildGraph builds a minimal passing DAG with the given IDs.
func coverBuildGraph(t *testing.T, ids ...string) *dag.DAG {
	t.Helper()
	d := dag.New()
	for _, id := range ids {
		if err := d.AddClaim(&ir.Claim{ID: id, Kind: "lemma"}); err != nil {
			t.Fatalf("AddClaim(%q): %v", id, err)
		}
	}
	return d
}

// coverAtt returns a fully populated accepted attestation suitable for all conditions.
func coverAtt(claimID string) *ir.Attestation {
	return &ir.Attestation{
		ClaimID:        claimID,
		Outcome:        string(ir.StatusAccepted),
		Assurance:      ir.AssuranceFormalKernel,
		SelfDigest:     "sha256:aa" + claimID,
		StartFreshness: "sha256:s" + claimID,
		EndFreshness:   "sha256:e" + claimID,
		Checker:        ir.CheckerIdentity{ProtocolVersion: 2},
		ObligationResults: []ir.ObligationResult{
			{ID: "ob-1", Verdict: "pass"},
		},
	}
}

// TestRelease_WritesManifest verifies that Release writes release-manifest.json
// when Gate.ProjectRoot is set and the release passes.
func TestRelease_WritesManifest(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	projRoot := t.TempDir()
	g := &release.Gate{OutputDir: outDir, ProjectRoot: projRoot}

	graph := coverBuildGraph(t, "c1", "c2")
	atts := map[string]*ir.Attestation{
		"c1": coverAtt("c1"),
		"c2": coverAtt("c2"),
	}
	pol := policy.ReleasePolicy{
		Version:        "v1",
		Target:         "c2",
		RequiredClaims: []string{"c1", "c2"},
	}

	pass, blockers, err := g.Release(graph, atts, pol, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !pass {
		t.Fatalf("expected pass, got blockers: %v", blockers)
	}

	manifestPath := filepath.Join(projRoot, release.ManifestFile)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("release-manifest.json not written: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("release-manifest.json is invalid JSON: %v", err)
	}
	if m["release_target"] != pol.Target {
		t.Errorf("release_target: got %v, want %q", m["release_target"], pol.Target)
	}
	if m["format_version"] != "2.0" {
		t.Errorf("format_version: got %v, want %q", m["format_version"], "2.0")
	}
}

// TestRelease_WritesManifestWithEvidence verifies that evidence entries are
// recorded in release-manifest.json when provided.
func TestRelease_WritesManifestWithEvidence(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	projRoot := t.TempDir()
	g := &release.Gate{OutputDir: outDir, ProjectRoot: projRoot}

	graph := coverBuildGraph(t, "c1")
	const certDigest = "sha256:deadbeef"
	att := coverAtt("c1")
	att.Evidence = []ir.EvidenceDescriptor{{Digest: certDigest}}
	att.Metadata = map[string]string{
		"cap_format_version": "v2",
		"ldlt_passes":        "true",
		"pivot_radius_ratio": "3.3e8",
	}
	atts := map[string]*ir.Attestation{"c1": att}
	pol := policy.ReleasePolicy{
		Version:        "v1",
		Target:         "c1",
		RequiredClaims: []string{"c1"},
	}
	evidence := []ir.EvidenceDescriptor{{
		Digest:    certDigest,
		PathHint:  "certs/primary.json",
		MediaType: "application/json",
	}}

	pass, _, err := g.Release(graph, atts, pol, evidence)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !pass {
		t.Fatal("expected pass")
	}

	// release-manifest.json must have the certificate entry.
	data, err := os.ReadFile(filepath.Join(projRoot, release.ManifestFile))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	certs, ok := manifest["certificates"].([]any)
	if !ok || len(certs) == 0 {
		t.Fatalf("expected at least one certificate entry, got: %v", manifest["certificates"])
	}
	cert := certs[0].(map[string]any)
	if cert["digest"] != certDigest {
		t.Errorf("cert digest: got %v, want %q", cert["digest"], certDigest)
	}
	if cert["path"] != "certs/primary.json" {
		t.Errorf("cert path: got %v, want %q", cert["path"], "certs/primary.json")
	}

	// release-snapshot.json must also be written with evidence.
	snap, err := os.ReadFile(filepath.Join(outDir, release.SnapshotFile))
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	var snapshot map[string]any
	if err := json.Unmarshal(snap, &snapshot); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	evList, ok := snapshot["evidence"].([]any)
	if !ok || len(evList) == 0 {
		t.Fatalf("snapshot: expected at least one evidence entry, got: %v", snapshot["evidence"])
	}
}

// TestC03_AssuranceNotInAllowedList verifies that C03 fails when an attestation
// uses an assurance that is neither forbidden nor in the allowed list.
func TestC03_AssuranceNotInAllowedList(t *testing.T) {
	t.Parallel()
	g := coverBuildGraph(t, "c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:   "c1",
			Outcome:   string(ir.StatusAccepted),
			Assurance: ir.AssuranceFormalKernel, // "formal-kernel" — not in allowed list below
		},
	}
	pol := policy.ReleasePolicy{
		Version:           "v1",
		AllowedAssurances: []string{"deterministic-cap"}, // formal-kernel not listed
	}

	results := release.EvaluateConditions(g, atts, pol, "")
	c03 := results[2]
	if c03.ID != release.CondAllAssurancesAllowed {
		t.Fatalf("results[2].ID = %q, want %q", c03.ID, release.CondAllAssurancesAllowed)
	}
	if c03.Passed {
		t.Error("C03 should fail when assurance is not in allowed list")
	}
	if c03.Blocker == "" {
		t.Error("C03 blocker should not be empty")
	}
}

// TestC03_ForbiddenTakesPrecedence verifies that a forbidden assurance is reported
// as forbidden (not "not in allowed list") even when allowed list is non-empty.
func TestC03_ForbiddenTakesPrecedence(t *testing.T) {
	t.Parallel()
	g := coverBuildGraph(t, "c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:   "c1",
			Outcome:   string(ir.StatusAccepted),
			Assurance: ir.AssuranceAIReview,
		},
	}
	pol := policy.ReleasePolicy{
		Version:             "v1",
		AllowedAssurances:   []string{"formal-kernel"},
		ForbiddenAssurances: []string{string(ir.AssuranceAIReview)},
	}

	results := release.EvaluateConditions(g, atts, pol, "")
	c03 := results[2]
	if c03.Passed {
		t.Error("C03 should fail for forbidden assurance")
	}
}

// TestC01_EmptyGraph verifies that C01 passes for a graph with no claims.
func TestC01_EmptyGraph(t *testing.T) {
	t.Parallel()
	g := dag.New()
	results := release.EvaluateConditions(g, nil, policy.ReleasePolicy{Version: "v1"}, "")
	c01 := results[0]
	if c01.ID != release.CondGlobalStatusAccepted {
		t.Fatalf("results[0].ID = %q, want C01", c01.ID)
	}
	if !c01.Passed {
		t.Errorf("C01 should pass for empty graph, blocker: %s", c01.Blocker)
	}
}

// TestC01_MissingAttestation verifies that C01 fails when a claim has no attestation.
func TestC01_MissingAttestation(t *testing.T) {
	t.Parallel()
	g := coverBuildGraph(t, "c1")
	// No attestations provided.
	results := release.EvaluateConditions(g, map[string]*ir.Attestation{}, policy.ReleasePolicy{}, "")
	c01 := results[0]
	if c01.Passed {
		t.Error("C01 should fail when attestation is missing")
	}
}

// coverBuildGraphWithChecker builds a minimal DAG where every claim has a
// checker_policy set, so C04 freshness checks apply.
func coverBuildGraphWithChecker(t *testing.T, ids ...string) *dag.DAG {
	t.Helper()
	d := dag.New()
	for _, id := range ids {
		if err := d.AddClaim(&ir.Claim{ID: id, Kind: "lemma", CheckerPolicy: "test-checker"}); err != nil {
			t.Fatalf("AddClaim(%q): %v", id, err)
		}
	}
	return d
}

// TestC04_MissingAttestation verifies that C04 fails when a claim has no attestation.
func TestC04_MissingAttestation(t *testing.T) {
	t.Parallel()
	g := coverBuildGraphWithChecker(t, "c1")
	results := release.EvaluateConditions(g, map[string]*ir.Attestation{}, policy.ReleasePolicy{}, "")
	c04 := results[3]
	if c04.ID != release.CondReplayConsistency {
		t.Fatalf("results[3].ID = %q, want C04", c04.ID)
	}
	if c04.Passed {
		t.Error("C04 should fail when attestation is missing")
	}
}

// TestC04_PartialFreshness verifies that C04 fails when freshness fields are partially empty.
func TestC04_PartialFreshness(t *testing.T) {
	t.Parallel()
	g := coverBuildGraphWithChecker(t, "c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:        "c1",
			Outcome:        string(ir.StatusAccepted),
			Assurance:      ir.AssuranceFormalKernel,
			SelfDigest:     "sha256:abc",
			StartFreshness: "sha256:s",
			// EndFreshness intentionally missing.
		},
	}
	results := release.EvaluateConditions(g, atts, policy.ReleasePolicy{}, "")
	c04 := results[3]
	if c04.Passed {
		t.Error("C04 should fail when EndFreshness is empty")
	}
}

// TestC05_AllSigned verifies that C05 passes when all attestations carry a valid
// Ed25519 signature that can be verified against a public key in keysDir.
func TestC05_AllSigned(t *testing.T) {
	t.Parallel()

	// Generate a real key pair, save the public key to a temp keysDir.
	keysDir := t.TempDir()
	key, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := key.SavePublic(filepath.Join(keysDir, "test.pub")); err != nil {
		t.Fatalf("SavePublic: %v", err)
	}

	// Build an attestation and sign it with the real private key.
	att := &ir.Attestation{
		ClaimID:   "c1",
		Outcome:   string(ir.StatusAccepted),
		Assurance: ir.AssuranceFormalKernel,
	}
	sig, err := key.Sign(att)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	att.Signature = &ir.AttestationSig{
		PubkeyFingerprint: sig.PubkeyFingerprint,
		Algorithm:         sig.Algorithm,
		Value:             sig.Value,
	}

	g := coverBuildGraph(t, "c1")
	atts := map[string]*ir.Attestation{"c1": att}
	pol := policy.ReleasePolicy{
		Version:                   "v1",
		RequireSignedAttestations: true,
	}
	results := release.EvaluateConditions(g, atts, pol, keysDir)
	// With RequireSignedAttestations, we get 5 conditions.
	c05 := results[4]
	if c05.ID != release.CondAttestationSignatures {
		t.Fatalf("results[4].ID = %q, want C05", c05.ID)
	}
	if !c05.Passed {
		t.Errorf("C05 should pass when all attestations are signed, blocker: %s", c05.Blocker)
	}
}

// TestC05_Unsigned verifies that C05 fails when an attestation has no signature.
func TestC05_Unsigned(t *testing.T) {
	t.Parallel()
	g := coverBuildGraph(t, "c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:   "c1",
			Outcome:   string(ir.StatusAccepted),
			Assurance: ir.AssuranceFormalKernel,
			// No Signature field.
		},
	}
	pol := policy.ReleasePolicy{
		Version:                   "v1",
		RequireSignedAttestations: true,
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	c05 := results[4]
	if c05.Passed {
		t.Error("C05 should fail when attestation has no signature")
	}
	if c05.Blocker == "" {
		t.Error("C05 blocker should not be empty for unsigned attestation")
	}
}

// TestC05_NotActivatedWithoutPolicy verifies that C05 is not evaluated when
// RequireSignedAttestations is false (default).
func TestC05_NotActivatedWithoutPolicy(t *testing.T) {
	t.Parallel()
	g := coverBuildGraph(t, "c1")
	atts := map[string]*ir.Attestation{
		"c1": {ClaimID: "c1", Outcome: string(ir.StatusAccepted), Assurance: ir.AssuranceFormalKernel},
	}
	pol := policy.ReleasePolicy{
		Version: "v1",
		// RequireSignedAttestations is false (default) — C05 should not appear.
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	for _, r := range results {
		if r.ID == release.CondAttestationSignatures {
			t.Error("C05 should not be evaluated when RequireSignedAttestations is false")
		}
	}
	if len(results) != 4 {
		t.Errorf("expected 4 conditions (no C05), got %d", len(results))
	}
}

// TestRelease_C05BlocksRelease verifies that release fails when
// RequireSignedAttestations is true and attestations are unsigned.
func TestRelease_C05BlocksRelease(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &release.Gate{OutputDir: outDir}

	graph := coverBuildGraph(t, "c1")
	atts := map[string]*ir.Attestation{
		"c1": coverAtt("c1"), // no Signature field
	}
	pol := policy.ReleasePolicy{
		Version:                   "v1",
		Target:                    "c1",
		RequireSignedAttestations: true,
	}

	pass, blockers, err := g.Release(graph, atts, pol, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if pass {
		t.Error("release should fail when C05 requires signatures but attestation is unsigned")
	}
	found := false
	for _, b := range blockers {
		if len(b) > 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected non-empty blockers, got: %v", blockers)
	}
}
func TestBuildClaimSummary(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	g := &release.Gate{OutputDir: outDir}

	d := dag.New()
	for _, id := range []string{"a", "b", "c"} {
		_ = d.AddClaim(&ir.Claim{ID: id, Kind: "lemma"})
	}
	atts := map[string]*ir.Attestation{
		"a": {ClaimID: "a", Outcome: string(ir.StatusAccepted), Assurance: ir.AssuranceFormalKernel,
			SelfDigest: "sha256:a", StartFreshness: "sha256:sa", EndFreshness: "sha256:ea",
			Checker:           ir.CheckerIdentity{ProtocolVersion: 2},
			ObligationResults: []ir.ObligationResult{{ID: "ob-1", Verdict: "pass"}}},
		"b": {ClaimID: "b", Outcome: string(ir.StatusRejected), Assurance: ir.AssuranceFormalKernel,
			Checker:           ir.CheckerIdentity{ProtocolVersion: 2},
			ObligationResults: []ir.ObligationResult{{ID: "ob-1", Verdict: "fail"}}},
		// c has no attestation → open
	}
	pol := policy.ReleasePolicy{Version: "v1", Target: "a"}

	_, _, err := g.Release(d, atts, pol, nil)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(outDir, release.StatusFile))
	var rs release.ReleaseStatus
	json.Unmarshal(data, &rs) //nolint — already validated in other tests
	if rs.ClaimSummary == nil {
		t.Fatal("claim_summary should not be nil")
	}
	if rs.ClaimSummary.Accepted != 1 {
		t.Errorf("accepted: got %d, want 1", rs.ClaimSummary.Accepted)
	}
	if rs.ClaimSummary.Rejected != 1 {
		t.Errorf("rejected: got %d, want 1", rs.ClaimSummary.Rejected)
	}
	if rs.ClaimSummary.Open != 1 {
		t.Errorf("open: got %d, want 1", rs.ClaimSummary.Open)
	}
}
