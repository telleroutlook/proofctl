package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// TestLoadCachedAttestation_CorruptedJSON checks that a corrupted attestation file
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
