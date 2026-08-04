package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/telleroutlook/proofctl/internal/kernel/bundle"
)

// makeBundle creates a minimal well-formed bundle directory for testing.
// attestations maps claim_id → obligations all-pass (true) or one-fail (false).
func makeBundle(t *testing.T, rootClaim string, attestations map[string]bool) string {
	t.Helper()
	dir := t.TempDir()

	attestDir := filepath.Join(dir, "attestations")
	if err := os.MkdirAll(attestDir, 0o755); err != nil {
		t.Fatalf("mkdir attestations: %v", err)
	}

	type oblResult struct {
		ID      string `json:"id"`
		Verdict string `json:"verdict"`
	}
	type attFile struct {
		ProtocolVersion     int         `json:"protocol_version"`
		ClaimID             string      `json:"claim_id"`
		ClaimIdentityDigest string      `json:"claim_identity_digest"`
		ObligationResults   []oblResult `json:"obligation_results"`
	}

	var memberDigests []bundle.ManifestMemberDigest
	for claimID, pass := range attestations {
		verdict := "fail"
		if pass {
			verdict = "pass"
		}
		att := attFile{
			ProtocolVersion:     2,
			ClaimID:             claimID,
			ClaimIdentityDigest: "sha256:identity-" + claimID,
			ObligationResults:   []oblResult{{ID: "obl-1", Verdict: verdict}},
		}
		data, _ := json.MarshalIndent(att, "", "  ")
		attPath := filepath.Join(attestDir, claimID+".json")
		if err := os.WriteFile(attPath, data, 0o644); err != nil {
			t.Fatalf("write attestation: %v", err)
		}
		relPath := "attestations/" + claimID + ".json"
		memberDigests = append(memberDigests, bundle.ManifestMemberDigest{
			Path:   relPath,
			Digest: computeDigest(data),
		})
	}

	manifest := bundle.Manifest{
		FormatVersion:          "2",
		RootClaim:              rootClaim,
		GraphRootDigest:        "sha256:graph111",
		PolicyDigest:           "sha256:policy222",
		StateDerivationVersion: "v2.0-M25",
		Members:                memberDigests,
	}
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifestData, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return dir
}

// ── verifyBundle ──────────────────────────────────────────────────────────────

func TestVerifyBundle_Released(t *testing.T) {
	t.Parallel()
	dir := makeBundle(t, "thm-main", map[string]bool{"thm-main": true})
	result, err := verifyBundle(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Released {
		t.Errorf("expected released=true, got false; blockers: %v", result.Blockers)
	}
	if result.RootState != "GLOBALLY_VERIFIED" {
		t.Errorf("expected root_state=GLOBALLY_VERIFIED, got %q", result.RootState)
	}
}

func TestVerifyBundle_NotReleased_FailingObligation(t *testing.T) {
	t.Parallel()
	dir := makeBundle(t, "thm-main", map[string]bool{"thm-main": false})
	result, err := verifyBundle(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Released {
		t.Error("expected released=false when obligation fails")
	}
	if len(result.Blockers) == 0 {
		t.Error("expected blockers for failing claim")
	}
}

func TestVerifyBundle_NotReleased_NoRootAttestation(t *testing.T) {
	t.Parallel()
	dir := makeBundle(t, "thm-main", map[string]bool{"other-claim": true})
	result, err := verifyBundle(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Released {
		t.Error("expected released=false when root claim has no attestation")
	}
}

func TestVerifyBundle_MemberDigestMismatch(t *testing.T) {
	t.Parallel()
	dir := makeBundle(t, "thm-main", map[string]bool{"thm-main": true})

	// Tamper with attestation after manifest is written.
	attPath := filepath.Join(dir, "attestations", "thm-main.json")
	if err := os.WriteFile(attPath, []byte(`{"claim_id":"thm-main","tampered":true}`), 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	result, err := verifyBundle(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Released {
		t.Error("expected released=false after member digest mismatch (INV-12)")
	}
	if len(result.Blockers) == 0 {
		t.Error("expected blockers for digest mismatch")
	}
}

func TestVerifyBundle_MissingManifest(t *testing.T) {
	t.Parallel()
	_, err := verifyBundle(t.TempDir(), "")
	if err == nil {
		t.Error("expected error for missing manifest.json")
	}
}

func TestVerifyBundle_InvalidManifestJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := verifyBundle(dir, "")
	if err == nil {
		t.Error("expected error for invalid manifest JSON")
	}
}

func TestVerifyBundle_WrongFormatVersion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifest := bundle.Manifest{FormatVersion: "1", RootClaim: "x"}
	data, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := verifyBundle(dir, "")
	if err == nil {
		t.Error("expected error for format_version=1")
	}
}

func TestVerifyBundle_NoAttestationsDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifest := bundle.Manifest{
		FormatVersion: "2",
		RootClaim:     "thm-main",
		Members:       []bundle.ManifestMemberDigest{},
	}
	data, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := verifyBundle(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Released {
		t.Error("expected released=false for bundle with no attestations dir")
	}
}

func TestVerifyBundle_MultipleClaims_AllPass(t *testing.T) {
	t.Parallel()
	dir := makeBundle(t, "thm-root", map[string]bool{
		"thm-root": true,
		"lem-a":    true,
		"lem-b":    true,
	})
	result, err := verifyBundle(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Released {
		t.Errorf("all claims pass, expected released=true; blockers: %v", result.Blockers)
	}
	if len(result.ClaimStates) != 3 {
		t.Errorf("expected 3 claim states, got %d", len(result.ClaimStates))
	}
}

func TestVerifyBundle_MultipleClaims_OneFails(t *testing.T) {
	t.Parallel()
	dir := makeBundle(t, "thm-root", map[string]bool{
		"thm-root": true,
		"lem-a":    false, // fails
	})
	result, err := verifyBundle(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// thm-root passes but lem-a fails → overall blockers present
	if len(result.Blockers) == 0 {
		t.Error("expected blockers when lem-a fails")
	}
}

// ── computeDigest ─────────────────────────────────────────────────────────────

func TestComputeDigest_Format(t *testing.T) {
	t.Parallel()
	d := computeDigest([]byte("hello"))
	if len(d) != 7+64 {
		t.Errorf("expected sha256:<64hex> (len %d), got %q (len %d)", 7+64, d, len(d))
	}
}

func TestComputeDigest_Deterministic(t *testing.T) {
	t.Parallel()
	a := computeDigest([]byte("x"))
	b := computeDigest([]byte("x"))
	if a != b {
		t.Error("computeDigest is not deterministic")
	}
}

func TestComputeDigest_Sensitive(t *testing.T) {
	t.Parallel()
	if computeDigest([]byte("a")) == computeDigest([]byte("b")) {
		t.Error("different inputs must produce different digests")
	}
}
