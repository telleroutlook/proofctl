package weil_test

import (
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/weil"
)

// TestDefectsByClaimID verifies that all known defects are accessible by claim ID.
func TestDefectsByClaimID(t *testing.T) {
	t.Parallel()
	m := weil.DefectsByClaimID()

	if len(m) != len(weil.KnownDefects) {
		t.Errorf("DefectsByClaimID: got %d entries, want %d", len(m), len(weil.KnownDefects))
	}

	for _, d := range weil.KnownDefects {
		got, ok := m[d.ClaimID]
		if !ok {
			t.Errorf("DefectsByClaimID: missing claim ID %q (defect %s)", d.ClaimID, d.ID)
			continue
		}
		if got.ID != d.ID {
			t.Errorf("DefectsByClaimID[%q].ID = %q, want %q", d.ClaimID, got.ID, d.ID)
		}
		if got.BlockReason == "" {
			t.Errorf("DefectsByClaimID[%q].BlockReason is empty", d.ClaimID)
		}
	}
}

// TestDefectsByID verifies lookup by D-number and presence of D4/D8/D18.
func TestDefectsByID(t *testing.T) {
	t.Parallel()
	m := weil.DefectsByID()

	if len(m) != len(weil.KnownDefects) {
		t.Errorf("DefectsByID: got %d entries, want %d", len(m), len(weil.KnownDefects))
	}

	for _, id := range []string{"D4", "D8", "D18"} {
		d, ok := m[id]
		if !ok {
			t.Errorf("DefectsByID: missing defect %q", id)
			continue
		}
		if d.ID != id {
			t.Errorf("DefectsByID[%q].ID = %q, want %q", id, d.ID, id)
		}
		if d.ClaimID == "" {
			t.Errorf("DefectsByID[%q].ClaimID is empty", id)
		}
		if d.BlockReason == "" {
			t.Errorf("DefectsByID[%q].BlockReason is empty", id)
		}
	}
}

// TestShadowAttestation verifies that BuildShadowAttestation produces a blocked attestation
// with shadow-review assurance and a non-empty block reason.
func TestShadowAttestation(t *testing.T) {
	t.Parallel()
	claim := &ir.Claim{
		ID: "lem-d4-kernel-bound",
		Statement: ir.Statement{
			Text:   "Kernel bound lemma D4",
			Digest: "sha256:abcd",
		},
	}
	defects := weil.DefectsByClaimID()
	defect, ok := defects["lem-d4-kernel-bound"]
	if !ok {
		t.Fatal("D4 defect not found by claim ID")
	}

	att := weil.BuildShadowAttestation(claim, defect)

	if att.ClaimID != claim.ID {
		t.Errorf("ClaimID = %q, want %q", att.ClaimID, claim.ID)
	}
	if att.Outcome != string(ir.StatusBlocked) {
		t.Errorf("Outcome = %q, want %q", att.Outcome, ir.StatusBlocked)
	}
	if att.Assurance != weil.ShadowAssurance {
		t.Errorf("Assurance = %q, want %q", att.Assurance, weil.ShadowAssurance)
	}
	if att.BlockReason == "" {
		t.Error("BlockReason must be non-empty for shadow attestation")
	}
	if att.StatementDigest != claim.Statement.Digest {
		t.Errorf("StatementDigest = %q, want %q", att.StatementDigest, claim.Statement.Digest)
	}
}

// TestOpenAttestation verifies that BuildOpenAttestation produces an open attestation
// with shadow-review assurance.
func TestOpenAttestation(t *testing.T) {
	t.Parallel()
	claim := &ir.Claim{
		ID: "def-frozen-model",
		Statement: ir.Statement{
			Text:   "Frozen model definition",
			Digest: "sha256:1234",
		},
	}

	att := weil.BuildOpenAttestation(claim)

	if att.ClaimID != claim.ID {
		t.Errorf("ClaimID = %q, want %q", att.ClaimID, claim.ID)
	}
	if att.Outcome != string(ir.StatusOpen) {
		t.Errorf("Outcome = %q, want %q", att.Outcome, ir.StatusOpen)
	}
	if att.Assurance != weil.ShadowAssurance {
		t.Errorf("Assurance = %q, want %q", att.Assurance, weil.ShadowAssurance)
	}
	if att.StatementDigest != claim.Statement.Digest {
		t.Errorf("StatementDigest = %q, want %q", att.StatementDigest, claim.Statement.Digest)
	}
}
