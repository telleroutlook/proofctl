package main

// cmd_helpers_test.go tests pure helper functions that don't require a full
// project setup or subprocess execution.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// ── replayModeLabel ───────────────────────────────────────────────────────────

func TestReplayModeLabel(t *testing.T) {
	t.Parallel()
	if !strings.Contains(replayModeLabel(false), "exact") {
		t.Error("non-semantic mode should contain 'exact'")
	}
	if !strings.Contains(replayModeLabel(true), "semantic") {
		t.Error("semantic mode should contain 'semantic'")
	}
}

// ── indentLines ───────────────────────────────────────────────────────────────

func TestIndentLines(t *testing.T) {
	t.Parallel()
	got := indentLines("line1\nline2\nline3", "  ")
	want := "  line1\n  line2\n  line3"
	if got != want {
		t.Errorf("indentLines = %q, want %q", got, want)
	}
}

func TestIndentLines_Empty(t *testing.T) {
	t.Parallel()
	got := indentLines("", ">>")
	if got != ">>" {
		t.Errorf("indentLines empty = %q, want %q", got, ">>")
	}
}

// ── extractSHA256InputsFromJSON ───────────────────────────────────────────────

func TestExtractSHA256InputsFromJSON_Present(t *testing.T) {
	t.Parallel()
	data := []byte(`{"sha256_inputs":{"file_a":"aabbcc","file_b":"ddeeff"}}`)
	got := extractSHA256InputsFromJSON(data)
	if got == nil {
		t.Fatal("expected non-nil map")
	}
	if got["file_a"] != "aabbcc" {
		t.Errorf("file_a = %q, want %q", got["file_a"], "aabbcc")
	}
}

func TestExtractSHA256InputsFromJSON_Missing(t *testing.T) {
	t.Parallel()
	data := []byte(`{"outcome":"accepted"}`)
	got := extractSHA256InputsFromJSON(data)
	if got != nil {
		t.Errorf("expected nil when sha256_inputs absent, got %v", got)
	}
}

func TestExtractSHA256InputsFromJSON_Invalid(t *testing.T) {
	t.Parallel()
	if got := extractSHA256InputsFromJSON([]byte("not json")); got != nil {
		t.Errorf("expected nil for invalid JSON, got %v", got)
	}
}

func TestExtractSHA256InputsFromJSON_NotObject(t *testing.T) {
	t.Parallel()
	// sha256_inputs is present but is a string, not a map.
	data := []byte(`{"sha256_inputs":"flat"}`)
	got := extractSHA256InputsFromJSON(data)
	if got != nil {
		t.Errorf("expected nil when sha256_inputs is not a map, got %v", got)
	}
}

// ── extractSHA256Inputs (file path version) ───────────────────────────────────

func TestExtractSHA256Inputs_ReadsFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.json")
	data := []byte(`{"sha256_inputs":{"src.lean":"deadbeef"}}`)
	if err := os.WriteFile(certPath, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := extractSHA256Inputs(certPath)
	if got == nil || got["src.lean"] != "deadbeef" {
		t.Errorf("expected src.lean=deadbeef, got %v", got)
	}
}

func TestExtractSHA256Inputs_MissingFile(t *testing.T) {
	t.Parallel()
	got := extractSHA256Inputs("/no/such/file.json")
	if got != nil {
		t.Errorf("expected nil for missing file, got %v", got)
	}
}

// ── buildDigestMismatchReason ─────────────────────────────────────────────────

func TestBuildDigestMismatchReason_NoInputs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// New cert with no sha256_inputs field.
	certPath := filepath.Join(dir, "cert.json")
	if err := os.WriteFile(certPath, []byte(`{"outcome":"accepted"}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	msg := buildDigestMismatchReason("sha256:aabb", "sha256:ccdd", certPath, dir)
	if !strings.Contains(msg, "digest mismatch") {
		t.Errorf("expected 'digest mismatch', got: %q", msg)
	}
}

func TestBuildDigestMismatchReason_ChangedInputs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	casRoot := filepath.Join(dir, "cas")

	wantDigest := "sha256:" + strings.Repeat("a", 64)
	hexPart := strings.Repeat("a", 64)
	blobDir := filepath.Join(casRoot, "sha256", hexPart[:2])
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Old cert: file_a = "old-hash"
	oldCert := map[string]any{"sha256_inputs": map[string]string{"file_a": "old-hash"}}
	oldData, _ := json.Marshal(oldCert)
	if err := os.WriteFile(filepath.Join(blobDir, hexPart[2:]), oldData, 0o644); err != nil {
		t.Fatalf("write old cert: %v", err)
	}

	// New cert: file_a = "new-hash"
	certPath := filepath.Join(dir, "new_cert.json")
	newCert := map[string]any{"sha256_inputs": map[string]string{"file_a": "new-hash"}}
	newData, _ := json.Marshal(newCert)
	if err := os.WriteFile(certPath, newData, 0o644); err != nil {
		t.Fatalf("write new cert: %v", err)
	}

	msg := buildDigestMismatchReason("sha256:bbbb", wantDigest, certPath, casRoot)
	if !strings.Contains(msg, "file_a") {
		t.Errorf("expected file_a in diff, got: %q", msg)
	}
	if !strings.Contains(msg, "old-hash") || !strings.Contains(msg, "new-hash") {
		t.Errorf("expected old/new hash values in diff, got: %q", msg)
	}
	if !strings.Contains(msg, "--semantic") {
		t.Errorf("expected --semantic hint in diff message, got: %q", msg)
	}
}

// ── casHasDigest ──────────────────────────────────────────────────────────────

func TestCasHasDigest_Present(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	digest := "sha256:" + strings.Repeat("c", 64)
	hexPart := strings.Repeat("c", 64)
	blobDir := filepath.Join(dir, "sha256", hexPart[:2])
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, hexPart[2:]), []byte("data"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !casHasDigest(dir, digest) {
		t.Error("expected casHasDigest to return true for present blob")
	}
}

func TestCasHasDigest_Absent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	digest := "sha256:" + strings.Repeat("d", 64)
	if casHasDigest(dir, digest) {
		t.Error("expected casHasDigest to return false for absent blob")
	}
}

func TestCasHasDigest_TooShort(t *testing.T) {
	t.Parallel()
	if casHasDigest(t.TempDir(), "sha256:ab") {
		t.Error("expected false for too-short digest")
	}
}

// ── computeOpenReasons ────────────────────────────────────────────────────────

func TestComputeOpenReasons(t *testing.T) {
	t.Parallel()
	g := dag.New()
	_ = g.AddClaim(&ir.Claim{
		ID:       "with-evidence",
		Evidence: []string{"sha256:" + strings.Repeat("e", 64)},
	})
	_ = g.AddClaim(&ir.Claim{
		ID:       "no-evidence",
		Evidence: nil,
	})
	_ = g.AddClaim(&ir.Claim{
		ID:       "attested",
		Evidence: nil,
	})

	attestations := map[string]*ir.Attestation{
		"attested": {ClaimID: "attested", Outcome: "accepted"},
	}

	reasons := computeOpenReasons(g, attestations)

	if r := reasons["with-evidence"]; r != "no attestation" {
		t.Errorf("with-evidence reason = %q, want 'no attestation'", r)
	}
	if r := reasons["no-evidence"]; r != "no evidence registered" {
		t.Errorf("no-evidence reason = %q, want 'no evidence registered'", r)
	}
	if _, ok := reasons["attested"]; ok {
		t.Error("attested claim should not appear in open reasons")
	}
}

// ── findZeroDigestClaims ──────────────────────────────────────────────────────

func TestFindZeroDigestClaims(t *testing.T) {
	t.Parallel()
	g := dag.New()
	_ = g.AddClaim(&ir.Claim{
		ID:        "zero",
		Statement: ir.Statement{Digest: zeroDigestPrefix},
	})
	_ = g.AddClaim(&ir.Claim{
		ID:        "empty",
		Statement: ir.Statement{Digest: ""},
	})
	_ = g.AddClaim(&ir.Claim{
		ID:        "real",
		Statement: ir.Statement{Digest: "sha256:" + strings.Repeat("f", 64)},
	})

	warn := findZeroDigestClaims(g)
	if !warn["zero"] {
		t.Error("expected 'zero' claim to be flagged")
	}
	if !warn["empty"] {
		t.Error("expected 'empty' claim to be flagged")
	}
	if warn["real"] {
		t.Error("expected 'real' claim not to be flagged")
	}
}

// ── loadReleaseTargetFromPolicy ───────────────────────────────────────────────

func TestLoadReleaseTargetFromPolicy_Valid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	polPath := filepath.Join(dir, "policy.json")
	data := []byte(`{"version":"1","target":"thm-main","allowed_assurances":["exact-replay"]}`)
	if err := os.WriteFile(polPath, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := loadReleaseTargetFromPolicy(dir, "policy.json")
	if got == nil {
		t.Fatal("expected non-nil target")
	}
	if *got != "thm-main" {
		t.Errorf("target = %q, want %q", *got, "thm-main")
	}
}

func TestLoadReleaseTargetFromPolicy_Missing(t *testing.T) {
	t.Parallel()
	got := loadReleaseTargetFromPolicy(t.TempDir(), "no-such-policy.json")
	if got != nil {
		t.Errorf("expected nil for missing policy file, got %q", *got)
	}
}

func TestLoadReleaseTargetFromPolicy_NoTarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	polPath := filepath.Join(dir, "policy.json")
	data := []byte(`{"version":"1","allowed_assurances":["exact-replay"]}`)
	if err := os.WriteFile(polPath, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := loadReleaseTargetFromPolicy(dir, "policy.json")
	if got != nil {
		t.Errorf("expected nil when target is absent, got %q", *got)
	}
}

func TestLoadReleaseTargetFromPolicy_EmptyPolicyFile(t *testing.T) {
	t.Parallel()
	got := loadReleaseTargetFromPolicy(t.TempDir(), "")
	if got != nil {
		t.Errorf("expected nil for empty policy file path, got %q", *got)
	}
}
