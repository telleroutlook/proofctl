package v2_test

import (
	"testing"

	v2 "github.com/telleroutlook/proofctl/pkg/protocol/v2"
)

func baseValidOutput(claimID string, obligationIDs []string) v2.CheckerOutputV2 {
	results := make([]v2.ObligationResult, len(obligationIDs))
	for i, id := range obligationIDs {
		results[i] = v2.ObligationResult{ID: id, Verdict: v2.VerdictPass}
	}
	return v2.CheckerOutputV2{
		ProtocolVersion:       v2.ProtocolVersion,
		ClaimID:               claimID,
		InputClosureDigest:    "sha256:aaa",
		CheckerIdentityDigest: "sha256:bbb",
		RuntimeIdentityDigest: "sha256:ccc",
		EvidenceUsed:          []string{"sha256:ev1"},
		ObligationResults:     results,
	}
}

// ── Happy path ────────────────────────────────────────────────────────────────

func TestValidateOutput_Valid(t *testing.T) {
	t.Parallel()
	out := baseValidOutput("thm-main", []string{"obl-a", "obl-b"})
	if err := v2.ValidateOutput(out, "thm-main", []string{"obl-a", "obl-b"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateOutput_NilExpected_EmptyReturned(t *testing.T) {
	t.Parallel()
	out := baseValidOutput("thm-main", nil)
	// nil expected, empty returned → both empty → pass
	if err := v2.ValidateOutput(out, "thm-main", nil); err != nil {
		t.Errorf("unexpected error for nil/nil: %v", err)
	}
}

func TestValidateOutput_SingleObligation(t *testing.T) {
	t.Parallel()
	out := baseValidOutput("c1", []string{"check-1"})
	if err := v2.ValidateOutput(out, "c1", []string{"check-1"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── Protocol version ──────────────────────────────────────────────────────────

func TestValidateOutput_WrongProtocolVersion(t *testing.T) {
	t.Parallel()
	out := baseValidOutput("thm-main", []string{"obl-a"})
	out.ProtocolVersion = 1
	err := v2.ValidateOutput(out, "thm-main", []string{"obl-a"})
	assertErrorContains(t, err, "PROTOCOL_VERSION", "wrong protocol version")
}

// ── Claim ID echo ─────────────────────────────────────────────────────────────

func TestValidateOutput_ClaimIDMismatch(t *testing.T) {
	t.Parallel()
	out := baseValidOutput("thm-main", []string{"obl-a"})
	err := v2.ValidateOutput(out, "thm-other", []string{"obl-a"})
	assertErrorContains(t, err, "CLAIM_ID_MISMATCH", "claim id mismatch")
}

// ── Obligation exact-set (INV-06) ─────────────────────────────────────────────

func TestValidateOutput_MissingObligation(t *testing.T) {
	t.Parallel()
	// Expected: [obl-a, obl-b]; Returned: [obl-a] — missing obl-b
	out := baseValidOutput("thm-main", []string{"obl-a"})
	err := v2.ValidateOutput(out, "thm-main", []string{"obl-a", "obl-b"})
	assertErrorContains(t, err, "OBLIGATION_MISSING", "INV-06 missing obligation")
}

func TestValidateOutput_ExtraObligation(t *testing.T) {
	t.Parallel()
	// Expected: [obl-a]; Returned: [obl-a, obl-b] — extra obl-b
	out := baseValidOutput("thm-main", []string{"obl-a", "obl-b"})
	err := v2.ValidateOutput(out, "thm-main", []string{"obl-a"})
	assertErrorContains(t, err, "OBLIGATION_EXTRA", "INV-06 extra obligation")
}

func TestValidateOutput_DuplicateObligation(t *testing.T) {
	t.Parallel()
	out := v2.CheckerOutputV2{
		ProtocolVersion: v2.ProtocolVersion,
		ClaimID:         "thm-main",
		ObligationResults: []v2.ObligationResult{
			{ID: "obl-a", Verdict: v2.VerdictPass},
			{ID: "obl-a", Verdict: v2.VerdictPass}, // duplicate
		},
	}
	err := v2.ValidateOutput(out, "thm-main", []string{"obl-a"})
	assertErrorContains(t, err, "OBLIGATION_DUPLICATE", "INV-06 duplicate obligation")
}

func TestValidateOutput_WrongIDSet(t *testing.T) {
	t.Parallel()
	// Expected: [obl-a]; Returned: [obl-b] — completely different IDs
	out := baseValidOutput("thm-main", []string{"obl-b"})
	err := v2.ValidateOutput(out, "thm-main", []string{"obl-a"})
	// Should report OBLIGATION_MISSING (obl-a absent) rather than EXTRA first.
	if err == nil {
		t.Fatal("expected error for wrong obligation ID set, got nil")
	}
}

// ── Verdict validation ────────────────────────────────────────────────────────

func TestValidateOutput_InvalidVerdict(t *testing.T) {
	t.Parallel()
	out := v2.CheckerOutputV2{
		ProtocolVersion: v2.ProtocolVersion,
		ClaimID:         "thm-main",
		ObligationResults: []v2.ObligationResult{
			{ID: "obl-a", Verdict: "accepted"}, // invalid — "accepted" is not allowed (INV-01)
		},
	}
	err := v2.ValidateOutput(out, "thm-main", []string{"obl-a"})
	assertErrorContains(t, err, "VERDICT_INVALID", "INV-01 invalid verdict")
}

func TestValidateOutput_FailVerdictIsValid(t *testing.T) {
	t.Parallel()
	out := v2.CheckerOutputV2{
		ProtocolVersion: v2.ProtocolVersion,
		ClaimID:         "thm-main",
		ObligationResults: []v2.ObligationResult{
			{ID: "obl-a", Verdict: v2.VerdictFail},
		},
	}
	// "fail" is a valid verdict — ValidateOutput should accept it.
	if err := v2.ValidateOutput(out, "thm-main", []string{"obl-a"}); err != nil {
		t.Errorf("verdict=fail should be accepted by ValidateOutput, got: %v", err)
	}
}

// ── AllObligationsPass ────────────────────────────────────────────────────────

func TestAllObligationsPass_AllPass(t *testing.T) {
	t.Parallel()
	out := baseValidOutput("thm-main", []string{"obl-a", "obl-b"})
	if !v2.AllObligationsPass(out) {
		t.Error("expected AllObligationsPass=true when all verdicts are pass")
	}
}

func TestAllObligationsPass_OneFail(t *testing.T) {
	t.Parallel()
	out := v2.CheckerOutputV2{
		ProtocolVersion: v2.ProtocolVersion,
		ClaimID:         "thm-main",
		ObligationResults: []v2.ObligationResult{
			{ID: "obl-a", Verdict: v2.VerdictPass},
			{ID: "obl-b", Verdict: v2.VerdictFail},
		},
	}
	if v2.AllObligationsPass(out) {
		t.Error("expected AllObligationsPass=false when any verdict is fail (INV-07)")
	}
}

func TestAllObligationsPass_Empty(t *testing.T) {
	t.Parallel()
	out := v2.CheckerOutputV2{ProtocolVersion: v2.ProtocolVersion, ClaimID: "x"}
	// Empty obligations → false (T-M31-P09: empty results cannot constitute a pass).
	// ValidateOutput would also reject this as OBLIGATION_EMPTY if expected set is non-nil.
	if v2.AllObligationsPass(out) {
		t.Error("empty obligation list should return false (T-M31-P09: cannot vacuously pass)")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func assertErrorContains(t *testing.T, err error, substr, context string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error containing %q, got nil", context, substr)
	}
	if !containsStr(err.Error(), substr) {
		t.Errorf("%s: expected error containing %q, got: %v", context, substr, err)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
