package verify

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/checker"
	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/runner"
	"github.com/telleroutlook/proofctl/pkg/protocol"
)

// mockRunner implements runner.Runner for tests.
type mockRunner struct {
	output []byte
	err    error
}

func (m *mockRunner) Run(_ context.Context, _ ir.CheckerIdentity, _ io.Reader) ([]byte, error) {
	return m.output, m.err
}

// driftRunner modifies blobFile during Run to simulate freshness drift.
type driftRunner struct {
	blobFile string
	output   []byte
}

func (d *driftRunner) Run(_ context.Context, _ ir.CheckerIdentity, _ io.Reader) ([]byte, error) {
	_ = os.WriteFile(d.blobFile, []byte("tampered content"), 0o644)
	return d.output, nil
}

// makeTestDAG builds a minimal single-claim DAG.
func makeTestDAG(claimID string) *dag.DAG {
	g := dag.New()
	_ = g.AddClaim(&ir.Claim{
		ID:   claimID,
		Kind: "lemma",
		Statement: ir.Statement{
			Text:   "test statement",
			Digest: "sha256:" + strings.Repeat("a", 64),
		},
	})
	return g
}

// makeTestCAS creates a temporary CAS, stores a blob, and returns the store,
// descriptor, and the on-disk path of the stored blob.
func makeTestCAS(t *testing.T) (*cas.Store, ir.EvidenceDescriptor, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := cas.New(filepath.Join(dir, "cas"))
	if err != nil {
		t.Fatalf("cas.New: %v", err)
	}

	blobContent := []byte("test evidence content")
	blobFile := filepath.Join(dir, "evidence.txt")
	if err := os.WriteFile(blobFile, blobContent, 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	f, err := os.Open(blobFile)
	if err != nil {
		t.Fatalf("open evidence: %v", err)
	}
	defer f.Close()
	digest, size, err := store.Store(f)
	if err != nil {
		t.Fatalf("store evidence: %v", err)
	}

	desc := ir.EvidenceDescriptor{
		MediaType: "text/plain",
		Digest:    digest,
		Size:      size,
		PathHint:  blobFile,
	}
	return store, desc, blobFile
}

// checkerOutput returns marshalled protocol.CheckerOutput for a given outcome.
func checkerOutput(outcome, assurance string) []byte {
	out := protocol.CheckerOutput{
		ProtocolVersion: protocol.ProtocolVersion,
		ClaimID:         "claim-1",
		Outcome:         outcome,
		Assurance:       assurance,
	}
	data, _ := json.Marshal(out)
	return data
}

// TestAdversarial_MaliciousClaimID_PathWrite verifies that Pipeline.Run rejects
// a claim ID containing path traversal sequences before writing any attestation file.
// On UNFIXED code writeAttestationAtomic joins the ID directly to a path, which
// would write the attestation outside the attestation directory.
func TestAdversarial_MaliciousClaimID_PathWrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestDir := filepath.Join(dir, "attestations")

	store, desc, _ := makeTestCAS(t)
	checkerID := ir.CheckerIdentity{ID: "test-checker", ProtocolVersion: 1}

	// Build a DAG that contains a claim whose ID embeds a path traversal sequence.
	maliciousID := "../escaped-payload"
	g := dag.New()
	_ = g.AddClaim(&ir.Claim{
		ID:   maliciousID,
		Kind: "lemma",
		Statement: ir.Statement{
			Text:   "test statement",
			Digest: "sha256:" + strings.Repeat("a", 64),
		},
	})

	p := &Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner:    &mockRunner{output: checkerOutput("accepted", "deterministic-cap")},
	}

	_, err := p.Run(context.Background(), maliciousID, checkerID, []ir.EvidenceDescriptor{desc}, "")
	// Must fail: the malicious ID must be rejected before writing any file.
	if err == nil {
		t.Fatal("expected error for malicious claim ID, got nil")
	}

	// Verify no file escaped the attestation directory.
	escapedPath := filepath.Join(dir, "escaped-payload.json")
	if _, statErr := os.Stat(escapedPath); statErr == nil {
		t.Fatalf("path traversal succeeded: file written outside attestDir at %s", escapedPath)
	}
}

func TestCacheHit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestDir := filepath.Join(dir, "attestations")

	store, desc, _ := makeTestCAS(t)
	g := makeTestDAG("claim-1")
	checkerID := ir.CheckerIdentity{ID: "test-checker", ProtocolVersion: 1}

	// Compute the exact cache key the pipeline would compute.
	claim := g.Claim("claim-1")
	cacheKey := checker.CacheKey(claim, nil, []ir.EvidenceDescriptor{desc}, checkerID, "", "")

	// Pre-store an attestation with the correct cache key.
	preAtt := &ir.Attestation{
		ClaimID:    "claim-1",
		Outcome:    "accepted",
		Assurance:  ir.AssuranceDeterministicCAP,
		CacheKey:   cacheKey,
		SelfDigest: "sha256:" + strings.Repeat("b", 64),
	}
	if err := writeAttestationAtomic(attestDir, "claim-1", preAtt); err != nil {
		t.Fatalf("pre-store attestation: %v", err)
	}

	// Runner must not be called on cache hit.
	p := &Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner:    &mockRunner{err: &runner.RunError{Code: runner.ExitUnavailable, Stderr: "should not be called"}},
	}

	res, err := p.Run(context.Background(), "claim-1", checkerID, []ir.EvidenceDescriptor{desc}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.CacheHit {
		t.Error("expected cache hit")
	}
	if res.Attestation.Outcome != "accepted" {
		t.Errorf("outcome: got %q want %q", res.Attestation.Outcome, "accepted")
	}
}

func TestCacheMissCheckerPass(t *testing.T) {
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
	if res.CacheHit {
		t.Error("expected cache miss")
	}
	if res.Attestation.Outcome != "accepted" {
		t.Errorf("outcome: got %q want %q", res.Attestation.Outcome, "accepted")
	}
	if res.Attestation.SelfDigest == "" {
		t.Error("expected non-empty SelfDigest")
	}

	// Attestation must be persisted.
	attPath := filepath.Join(attestDir, "claim-1.json")
	if _, err := os.Stat(attPath); err != nil {
		t.Errorf("attestation file not written: %v", err)
	}
}

func TestMissingEvidence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestDir := filepath.Join(dir, "attestations")

	store, err := cas.New(filepath.Join(dir, "cas"))
	if err != nil {
		t.Fatalf("cas.New: %v", err)
	}
	g := makeTestDAG("claim-1")
	checkerID := ir.CheckerIdentity{ID: "test-checker", ProtocolVersion: 1}

	badDesc := ir.EvidenceDescriptor{
		MediaType: "text/plain",
		Digest:    "sha256:" + strings.Repeat("f", 64),
		Size:      100,
	}

	p := &Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner:    &mockRunner{},
	}

	_, err = p.Run(context.Background(), "claim-1", checkerID, []ir.EvidenceDescriptor{badDesc}, "")
	if err == nil {
		t.Fatal("expected error for missing evidence, got nil")
	}
	if !strings.Contains(err.Error(), "MISSING_EVIDENCE") {
		t.Errorf("expected MISSING_EVIDENCE in error, got: %v", err)
	}
}

func TestFreshnessDrift(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestDir := filepath.Join(dir, "attestations")

	store, desc, blobFile := makeTestCAS(t)
	g := makeTestDAG("claim-1")
	checkerID := ir.CheckerIdentity{ID: "test-checker", ProtocolVersion: 1}

	p := &Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner:    &driftRunner{blobFile: blobFile, output: checkerOutput("accepted", "deterministic-cap")},
	}

	_, err := p.Run(context.Background(), "claim-1", checkerID, []ir.EvidenceDescriptor{desc}, "")
	if err == nil {
		t.Fatal("expected freshness violation error, got nil")
	}
	if !strings.Contains(err.Error(), "FRESHNESS_VIOLATION") {
		t.Errorf("expected FRESHNESS_VIOLATION, got: %v", err)
	}
}

func TestCheckerFail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestDir := filepath.Join(dir, "attestations")

	store, desc, _ := makeTestCAS(t)
	g := makeTestDAG("claim-1")
	checkerID := ir.CheckerIdentity{ID: "test-checker", ProtocolVersion: 1}

	// Exit 1: checker ran, claim rejected. The runner also provides output.
	p := &Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner: &mockRunner{
			output: checkerOutput("rejected", "deterministic-cap"),
			err:    &runner.RunError{Code: runner.ExitFail, Stderr: "assertion failed"},
		},
	}

	res, err := p.Run(context.Background(), "claim-1", checkerID, []ir.EvidenceDescriptor{desc}, "")
	if err != nil {
		t.Fatalf("unexpected error for ExitFail: %v", err)
	}
	if res.Attestation.Outcome != "rejected" {
		t.Errorf("outcome: got %q want %q", res.Attestation.Outcome, "rejected")
	}
}

func TestCheckerUnavailable(t *testing.T) {
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
		Runner: &mockRunner{
			err: &runner.RunError{Code: runner.ExitUnavailable, Stderr: "binary not found"},
		},
	}

	_, err := p.Run(context.Background(), "claim-1", checkerID, []ir.EvidenceDescriptor{desc}, "")
	if err == nil {
		t.Fatal("expected error for unavailable checker, got nil")
	}
	if !strings.Contains(err.Error(), "CHECKER_FAILED") {
		t.Errorf("expected CHECKER_FAILED in error, got: %v", err)
	}
}
