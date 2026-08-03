package attestation

import (
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// makeAttestation builds a minimal ir.Attestation for testing.
func makeAttestation(claimID, outcome string) ir.Attestation {
	return ir.Attestation{
		ClaimID:         claimID,
		StatementDigest: "sha256:" + repeat64('a'),
		Outcome:         outcome,
		Assurance:       ir.AssuranceFormalKernel,
	}
}

// repeat64 returns a 64-char string of the given byte.
func repeat64(b byte) string {
	s := make([]byte, 64)
	for i := range s {
		s[i] = b
	}
	return string(s)
}

// TestCombineZeroAttestations checks that Combine with zero attestations produces a valid global attestation.
func TestCombineZeroAttestations(t *testing.T) {
	t.Parallel()
	g := Combine(nil)
	if len(g.Attestations) != 0 {
		t.Errorf("expected empty attestations, got %v", g.Attestations)
	}
	if g.SelfDigestValue == "" {
		t.Error("expected non-empty self digest for zero attestations")
	}
	// Must have sha256: prefix.
	if len(g.SelfDigestValue) < 7 || g.SelfDigestValue[:7] != "sha256:" {
		t.Errorf("expected sha256: prefix in self digest, got %q", g.SelfDigestValue)
	}
}

// TestCombineMultiple checks that Combine with multiple attestations includes all claim IDs.
func TestCombineMultiple(t *testing.T) {
	t.Parallel()
	local := []ir.Attestation{
		makeAttestation("claim-1", string(ir.StatusAccepted)),
		makeAttestation("claim-2", string(ir.StatusAccepted)),
		makeAttestation("claim-3", string(ir.StatusRejected)),
	}
	g := Combine(local)
	if len(g.Attestations) != 3 {
		t.Errorf("expected 3 attestations, got %d", len(g.Attestations))
	}
	claimIDs := map[string]bool{}
	for _, a := range g.Attestations {
		claimIDs[a.ClaimID] = true
	}
	for _, want := range []string{"claim-1", "claim-2", "claim-3"} {
		if !claimIDs[want] {
			t.Errorf("missing claim ID %q in combined attestations", want)
		}
	}
}

// TestSelfDigestDeterministic checks that SelfDigest is deterministic for the same input.
func TestSelfDigestDeterministic(t *testing.T) {
	t.Parallel()
	local := []ir.Attestation{
		makeAttestation("claim-1", string(ir.StatusAccepted)),
	}
	g1 := Combine(local)
	g2 := Combine(local)

	d1 := g1.SelfDigest()
	d2 := g2.SelfDigest()
	if d1 != d2 {
		t.Errorf("SelfDigest not deterministic: %q vs %q", d1, d2)
	}
}

// TestSelfDigestChangesOnModification checks that SelfDigest changes when attestations change.
func TestSelfDigestChangesOnModification(t *testing.T) {
	t.Parallel()
	local1 := []ir.Attestation{
		makeAttestation("claim-1", string(ir.StatusAccepted)),
	}
	local2 := []ir.Attestation{
		makeAttestation("claim-1", string(ir.StatusRejected)), // outcome changed
	}

	g1 := Combine(local1)
	g2 := Combine(local2)

	if g1.SelfDigestValue == g2.SelfDigestValue {
		t.Error("expected different SelfDigest when attestation changes, got same")
	}
}

// TestSelfDigestStoredOnCombine checks that the SelfDigestValue field is set by Combine.
func TestSelfDigestStoredOnCombine(t *testing.T) {
	t.Parallel()
	local := []ir.Attestation{makeAttestation("claim-x", string(ir.StatusAccepted))}
	g := Combine(local)
	if g.SelfDigestValue == "" {
		t.Error("expected non-empty SelfDigestValue after Combine")
	}
	// The stored value should equal a fresh call to SelfDigest.
	if got := g.SelfDigest(); got != g.SelfDigestValue {
		t.Errorf("SelfDigestValue %q != SelfDigest() %q", g.SelfDigestValue, got)
	}
}

// TestSelfDigestEmptyVsNonEmpty checks that empty and non-empty attestation slices have different digests.
func TestSelfDigestEmptyVsNonEmpty(t *testing.T) {
	t.Parallel()
	empty := Combine(nil)
	nonEmpty := Combine([]ir.Attestation{makeAttestation("c1", string(ir.StatusAccepted))})
	if empty.SelfDigestValue == nonEmpty.SelfDigestValue {
		t.Error("expected different SelfDigest for empty vs non-empty attestations")
	}
}
