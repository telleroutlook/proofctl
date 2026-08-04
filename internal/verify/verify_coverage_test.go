package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/runner"
	protov2 "github.com/telleroutlook/proofctl/pkg/protocol/v2"
)

// TestWriteAttestationAtomic_InvalidClaimID verifies that writeAttestationAtomic
// returns an error immediately for an invalid claim ID (path traversal guard).
func TestWriteAttestationAtomic_InvalidClaimID(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	att := &ir.Attestation{ClaimID: "../escaped"}
	err := writeAttestationAtomic(dir, "../escaped", att)
	if err == nil {
		t.Fatal("expected error for invalid claim ID, got nil")
	}
}

// TestWriteAttestationAtomic_ReadOnlyDir verifies that writeAttestationAtomic
// returns an error when the attestation directory cannot be created.
func TestWriteAttestationAtomic_ReadOnlyDir(t *testing.T) {
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("running as root — permission checks are bypassed")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	defer func() { _ = os.Chmod(parent, 0o755) }()

	att := &ir.Attestation{ClaimID: "claim-1"}
	err := writeAttestationAtomic(filepath.Join(parent, "attest"), "claim-1", att)
	if err == nil {
		t.Fatal("expected error writing to read-only parent dir, got nil")
	}
}

// TestParseCheckerOutputV2_InvalidJSON verifies that invalid JSON is rejected.
func TestParseCheckerOutputV2_InvalidJSON(t *testing.T) {
	t.Parallel()
	var out protov2.CheckerOutputV2
	err := json.Unmarshal([]byte(`not json`), &out)
	if err == nil {
		t.Fatal("expected error for non-JSON output, got nil")
	}
}

// TestValidateOutputV2_MissingObligation verifies that a v2 output missing
// expected obligations is rejected.
func TestValidateOutputV2_MissingObligation(t *testing.T) {
	t.Parallel()
	out := protov2.CheckerOutputV2{
		ProtocolVersion: 2,
		ClaimID:         "c1",
		ObligationResults: []protov2.ObligationResult{
			{ID: "obl-a", Verdict: protov2.VerdictPass},
		},
	}
	err := protov2.ValidateOutput(out, "c1", []string{"obl-a", "obl-b"})
	if err == nil {
		t.Fatal("expected error for missing obligation, got nil")
	}
}

// TestValidateOutputV2_InvalidVerdict verifies that an invalid verdict is rejected.
func TestValidateOutputV2_InvalidVerdict(t *testing.T) {
	t.Parallel()
	out := protov2.CheckerOutputV2{
		ProtocolVersion: 2,
		ClaimID:         "c1",
		ObligationResults: []protov2.ObligationResult{
			{ID: "obl-a", Verdict: "accepted"},
		},
	}
	err := protov2.ValidateOutput(out, "c1", []string{"obl-a"})
	if err == nil {
		t.Fatal("expected error for invalid verdict 'accepted', got nil")
	}
}

// TestIsRunError_NonRunError verifies that isRunError returns false for a
// non-*RunError error type.
func TestIsRunError_NonRunError(t *testing.T) {
	t.Parallel()
	var target *runner.RunError
	if isRunError(fmt.Errorf("plain error"), &target) {
		t.Error("expected false for plain error, got true")
	}
	if target != nil {
		t.Error("target should remain nil")
	}
}

// TestProtocolErrorPath exercises the ExitProtocolError branch in Pipeline.Run.
func TestProtocolErrorPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store, desc, _ := makeTestCAS(t)
	g := makeTestDAG("claim-1")
	checkerID := ir.CheckerIdentity{ID: "test-checker", ProtocolVersion: 1}

	p := &Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: filepath.Join(dir, "attestations"),
		Runner: &mockRunner{
			err: &runner.RunError{Code: runner.ExitProtocolError, Stderr: "bad protocol"},
		},
	}

	_, err := p.Run(context.Background(), "claim-1", checkerID, []ir.EvidenceDescriptor{desc}, "")
	if err == nil {
		t.Fatal("expected error for protocol error, got nil")
	}
	if !strings.Contains(err.Error(), "CHECKER_FAILED") {
		t.Errorf("expected CHECKER_FAILED in error, got: %v", err)
	}
}

// TestUnknownExitCodePath exercises the default (unexpected exit code) branch.
func TestUnknownExitCodePath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store, desc, _ := makeTestCAS(t)
	g := makeTestDAG("claim-1")
	checkerID := ir.CheckerIdentity{ID: "test-checker", ProtocolVersion: 1}

	p := &Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: filepath.Join(dir, "attestations"),
		// Code 99 is not ExitFail/Unavailable/ProtocolError → default branch
		Runner: &mockRunner{
			err: &runner.RunError{Code: 99, Stderr: "unexpected"},
		},
	}

	_, err := p.Run(context.Background(), "claim-1", checkerID, []ir.EvidenceDescriptor{desc}, "")
	if err == nil {
		t.Fatal("expected error for unknown exit code, got nil")
	}
}

// causes loadCachedAttestation to return an error, not a panic.
func TestLoadCachedAttestation_CorruptedJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestDir := filepath.Join(dir, "attestations")
	if err := os.MkdirAll(attestDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Write corrupted JSON to the attestation file.
	path := filepath.Join(attestDir, "claim-1.json")
	if err := os.WriteFile(path, []byte(`{not valid json`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	store, err := cas.New(filepath.Join(dir, "cas"))
	if err != nil {
		t.Fatalf("cas.New: %v", err)
	}
	g := makeTestDAG("claim-1")
	p := &Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner:    &mockRunner{},
	}

	// loadCachedAttestation must return an error, never panic.
	result, err := p.loadCachedAttestation("claim-1", "any-key")
	if err == nil {
		t.Error("expected error for corrupted JSON, got nil")
	}
	if result != nil {
		t.Error("expected nil result for corrupted JSON")
	}
}

// TestLoadCachedAttestation_MissingCacheKey checks that an attestation file with
// no cache_key field (empty string) is treated as a cache miss, not a hit.
func TestLoadCachedAttestation_MissingCacheKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestDir := filepath.Join(dir, "attestations")

	// Write an attestation with no cache_key.
	attNoCacheKey := &ir.Attestation{
		ClaimID:   "claim-1",
		Outcome:   "accepted",
		Assurance: ir.AssuranceDeterministicCAP,
		CacheKey:  "", // intentionally empty
	}
	data, err := json.MarshalIndent(attNoCacheKey, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.MkdirAll(attestDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(attestDir, "claim-1.json"), data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	store, err := cas.New(filepath.Join(dir, "cas"))
	if err != nil {
		t.Fatalf("cas.New: %v", err)
	}
	g := makeTestDAG("claim-1")
	p := &Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner:    &mockRunner{},
	}

	// The cache key we look for is non-empty, so empty stored key is a miss.
	result, err := p.loadCachedAttestation("claim-1", "expected-cache-key")
	if err == nil {
		t.Error("expected cache-miss error for key mismatch, got nil")
	}
	if result != nil {
		t.Error("expected nil result for cache miss")
	}
}

// TestMissingCacheFile checks that loadCachedAttestation returns an error (not a panic)
// when the attestation file does not exist.
func TestMissingCacheFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestDir := filepath.Join(dir, "attestations")

	store, err := cas.New(filepath.Join(dir, "cas"))
	if err != nil {
		t.Fatalf("cas.New: %v", err)
	}
	g := makeTestDAG("claim-1")
	p := &Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner:    &mockRunner{},
	}

	result, err := p.loadCachedAttestation("claim-1", "some-key")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
	if result != nil {
		t.Error("expected nil result for missing file")
	}
}

// TestEvidenceEmptyDigest checks that evidence with an empty digest causes the
// CAS verification step to fail gracefully rather than panicking.
func TestEvidenceEmptyDigest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestDir := filepath.Join(dir, "attestations")

	store, err := cas.New(filepath.Join(dir, "cas"))
	if err != nil {
		t.Fatalf("cas.New: %v", err)
	}
	g := makeTestDAG("claim-1")

	emptyDigestDesc := ir.EvidenceDescriptor{
		MediaType: "text/plain",
		Digest:    "", // intentionally empty
		Size:      10,
	}

	p := &Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner:    &mockRunner{},
	}

	_, runErr := p.Run(context.Background(), "claim-1", ir.CheckerIdentity{ID: "test", ProtocolVersion: 1},
		[]ir.EvidenceDescriptor{emptyDigestDesc}, "")
	if runErr == nil {
		t.Fatal("expected error for empty evidence digest, got nil")
	}
	// The error should mention missing evidence (MISSING_EVIDENCE), not panic.
	if !strings.Contains(runErr.Error(), "MISSING_EVIDENCE") {
		t.Errorf("expected MISSING_EVIDENCE in error, got: %v", runErr)
	}
}

// TestPostRunAttestationFileIsValidJSON checks that after a successful run,
// the persisted attestation file is valid JSON containing the correct claim ID.
func TestPostRunAttestationFileIsValidJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestDir := filepath.Join(dir, "attestations")

	store, desc, _ := makeTestCAS(t)
	g := makeTestDAG("claim-1")
	checkerID := ir.CheckerIdentity{ID: "test-checker", ProtocolVersion: 1}

	p := &Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner:    &mockRunner{output: checkerOutput("accepted", "deterministic-cap")},
	}

	res, err := p.Run(context.Background(), "claim-1", checkerID, []ir.EvidenceDescriptor{desc}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	attPath := filepath.Join(attestDir, "claim-1.json")
	data, err := os.ReadFile(attPath)
	if err != nil {
		t.Fatalf("cannot read attestation file: %v", err)
	}

	var decoded ir.Attestation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("attestation file is not valid JSON: %v", err)
	}
	if decoded.ClaimID != "claim-1" {
		t.Errorf("attestation claim_id: got %q want %q", decoded.ClaimID, "claim-1")
	}
	if decoded.SelfDigest == "" {
		t.Error("attestation self_digest must not be empty")
	}
	if decoded.SelfDigest != res.Attestation.SelfDigest {
		t.Errorf("on-disk self_digest %q does not match in-memory %q", decoded.SelfDigest, res.Attestation.SelfDigest)
	}
}
