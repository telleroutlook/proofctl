// Package adversarial contains tests that enforce architecture-level invariants
// (INV-01 through INV-12) for the proofctl v2 kernel.
//
// Tests in this package are the machine-readable enforcement of the invariants
// declared in the Canvas document. A failing test here is a blocking invariant
// violation, not just a quality issue.
//
// INV status:
//   - INV-01: ACTIVE (TestINV01_NoWritablePassField, TestINV01_ObligationVerdictConstants)
//   - INV-06: ACTIVE (TestINV06_ObligationExactSet_*)
//   - INV-07: ACTIVE (TestINV07_PartialEvidenceFailure_*)
//   - INV-09: ACTIVE (TestINV09_StalenessOnIdentityChange_*)
package adversarial

import (
	"reflect"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/kernel/derive"
	"github.com/telleroutlook/proofctl/internal/kernel/identity"
	v2 "github.com/telleroutlook/proofctl/pkg/protocol/v2"
)

// ── INV-01: No writable PASS/RELEASED fields in v2 checker output ────────────

// TestINV01_NoWritablePassField verifies that CheckerOutputV2 does not contain
// any field named Outcome, Assurance, Status, Released, Accepted, or Verified.
//
// INV-01: user input must not contain writable PASS/RELEASED fields.
// A checker cannot assert "accepted" — it can only report obligation verdicts.
func TestINV01_NoWritablePassField(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"Outcome", "Assurance", "Status", "Released", "Accepted", "Verified", "Pass", "OK",
	}

	typ := reflect.TypeOf(v2.CheckerOutputV2{})
	for _, name := range forbidden {
		if _, ok := typ.FieldByName(name); ok {
			t.Errorf("INV-01 VIOLATED: CheckerOutputV2 has field %q — "+
				"checkers must not assert acceptance directly; use ObligationResults instead", name)
		}
	}

	// Verdict must be a typed string, not bool.
	oblTyp := reflect.TypeOf(v2.ObligationResult{})
	verdictField, ok := oblTyp.FieldByName("Verdict")
	if !ok {
		t.Fatal("INV-01: ObligationResult must have a Verdict field")
	}
	if verdictField.Type.Kind() == reflect.Bool {
		t.Error("INV-01 VIOLATED: ObligationResult.Verdict must not be bool")
	}
}

// TestINV01_ObligationVerdictConstants verifies only "pass" and "fail" are valid verdicts.
func TestINV01_ObligationVerdictConstants(t *testing.T) {
	t.Parallel()

	if v2.VerdictPass != "pass" {
		t.Errorf("VerdictPass must be %q, got %q", "pass", v2.VerdictPass)
	}
	if v2.VerdictFail != "fail" {
		t.Errorf("VerdictFail must be %q, got %q", "fail", v2.VerdictFail)
	}

	banned := []string{"accept", "verif", "release", "ok", "pass=true"}
	for _, b := range banned {
		if strings.Contains(strings.ToLower(string(v2.VerdictPass)), b) {
			t.Errorf("VerdictPass %q must not contain %q", v2.VerdictPass, b)
		}
	}
}

// ── INV-06: Obligation exact-set validation ───────────────────────────────────

// TestINV06_ObligationExactSet_MissingID verifies that a missing obligation ID
// in the checker result causes BLOCKED (INV-06).
func TestINV06_ObligationExactSet_MissingID(t *testing.T) {
	t.Parallel()
	// Contract declares 3 obligations; checker returns only 2 → ObligationSetMismatch.
	in := derive.DeriveInput{
		ClaimID:             "thm-main",
		CurrentIdentity:     "sha256:aaaa",
		AttestationIdentity: "sha256:aaaa",
		Evidence:            derive.EvidencePresent,
		ObligationSet:       derive.ObligationSetMismatch, // missing obligation
		DepStates:           map[string]derive.ClaimStateV2{},
		RequiredDepStates:   map[string]derive.ClaimStateV2{},
	}
	got := derive.DeriveClaimState(in)
	if got != derive.StateBlocked {
		t.Errorf("INV-06 VIOLATED: missing obligation ID must produce BLOCKED, got %s", got)
	}
}

// TestINV06_ObligationExactSet_ExtraID verifies that an extra (unknown) obligation ID
// causes BLOCKED (INV-06: must be exact set, not superset).
func TestINV06_ObligationExactSet_ExtraID(t *testing.T) {
	t.Parallel()
	// Represented as Mismatch because the set is wrong (superset, not exact).
	in := derive.DeriveInput{
		ClaimID:             "thm-main",
		CurrentIdentity:     "sha256:aaaa",
		AttestationIdentity: "sha256:aaaa",
		Evidence:            derive.EvidencePresent,
		ObligationSet:       derive.ObligationSetMismatch, // extra obligation
		DepStates:           map[string]derive.ClaimStateV2{},
		RequiredDepStates:   map[string]derive.ClaimStateV2{},
	}
	got := derive.DeriveClaimState(in)
	if got != derive.StateBlocked {
		t.Errorf("INV-06 VIOLATED: extra obligation ID must produce BLOCKED, got %s", got)
	}
}

// TestINV06_ObligationExactSet_Pass verifies that exactly the right obligation set
// with all verdicts passing produces GLOBALLY_VERIFIED (no deps required).
func TestINV06_ObligationExactSet_Pass(t *testing.T) {
	t.Parallel()
	in := derive.DeriveInput{
		ClaimID:             "thm-main",
		CurrentIdentity:     "sha256:aaaa",
		AttestationIdentity: "sha256:aaaa",
		Evidence:            derive.EvidencePresent,
		ObligationSet:       derive.ObligationSetPass, // exact set, all pass
		DepStates:           map[string]derive.ClaimStateV2{},
		RequiredDepStates:   map[string]derive.ClaimStateV2{},
	}
	got := derive.DeriveClaimState(in)
	if got != derive.StateGloballyVerified {
		t.Errorf("INV-06: exact obligation set all-pass must produce GLOBALLY_VERIFIED, got %s", got)
	}
}

// ── INV-07: Required evidence failure → whole claim fails ────────────────────

// TestINV07_PartialEvidenceFailure_SingleFail verifies that a single failing
// obligation (representing a failing evidence piece) produces BLOCKED.
func TestINV07_PartialEvidenceFailure_SingleFail(t *testing.T) {
	t.Parallel()
	// INV-07: any required evidence failure → BLOCKED, no partial success allowed.
	in := derive.DeriveInput{
		ClaimID:             "thm-main",
		CurrentIdentity:     "sha256:aaaa",
		AttestationIdentity: "sha256:aaaa",
		Evidence:            derive.EvidencePresent,
		ObligationSet:       derive.ObligationSetFail, // ≥1 obligation failed
		DepStates:           map[string]derive.ClaimStateV2{},
		RequiredDepStates:   map[string]derive.ClaimStateV2{},
	}
	got := derive.DeriveClaimState(in)
	if got != derive.StateBlocked {
		t.Errorf("INV-07 VIOLATED: any obligation fail must produce BLOCKED (no partial success), got %s", got)
	}
}

// TestINV07_PartialEvidenceFailure_NoUpgrade verifies that BLOCKED cannot be
// upgraded by replay or release flags — fail is fail.
func TestINV07_PartialEvidenceFailure_NoUpgrade(t *testing.T) {
	t.Parallel()
	// Even with replay and release root flags set, a failing obligation → BLOCKED.
	in := derive.DeriveInput{
		ClaimID:             "thm-main",
		CurrentIdentity:     "sha256:aaaa",
		AttestationIdentity: "sha256:aaaa",
		Evidence:            derive.EvidencePresent,
		ObligationSet:       derive.ObligationSetFail,
		DepStates:           map[string]derive.ClaimStateV2{},
		RequiredDepStates:   map[string]derive.ClaimStateV2{},
		HasReplay:           true,
		IsReleaseRoot:       true,
		HasSignedManifest:   true,
	}
	got := derive.DeriveClaimState(in)
	if got != derive.StateBlocked {
		t.Errorf("INV-07 VIOLATED: failing obligation must stay BLOCKED even with replay+release flags, got %s", got)
	}
}

// ── INV-09: Identity change → STALE propagation ──────────────────────────────

// TestINV09_StalenessOnIdentityChange verifies that changing any field in the
// identity closure produces a different digest, and that a mismatched
// AttestationIdentity causes STALE.
func TestINV09_StalenessOnIdentityChange(t *testing.T) {
	t.Parallel()

	base := identity.ClaimIdentityInputs{
		CanonicalStatement:    "thm-main: radius ≥ 0.30",
		OrderedDepIdentities:  []string{"sha256:dep1"},
		ContractDigest:        "sha256:contract",
		CheckerIdentityDigest: "sha256:checker",
		RuntimeIdentityDigest: "sha256:runtime",
		PolicyDigest:          "sha256:policy",
		GraphRootDigest:       "sha256:graph",
	}
	originalIdentity := identity.Compute(base)

	// Simulate stored attestation with the original identity.
	// Now change the checker digest (e.g. checker was updated).
	modified := base
	modified.CheckerIdentityDigest = "sha256:new-checker-version"
	newIdentity := identity.Compute(modified)

	if originalIdentity == newIdentity {
		t.Fatal("INV-09: changing CheckerIdentityDigest must produce a different claim identity")
	}

	// proofverify would call DeriveClaimState with currentIdentity=newIdentity
	// and attestationIdentity=originalIdentity → must return STALE.
	in := derive.DeriveInput{
		ClaimID:             "thm-main",
		CurrentIdentity:     newIdentity,
		AttestationIdentity: originalIdentity, // stored with old identity
		Evidence:            derive.EvidencePresent,
		ObligationSet:       derive.ObligationSetPass,
		DepStates:           map[string]derive.ClaimStateV2{},
		RequiredDepStates:   map[string]derive.ClaimStateV2{},
	}
	got := derive.DeriveClaimState(in)
	if got != derive.StateStale {
		t.Errorf("INV-09 VIOLATED: identity mismatch must produce STALE, got %s", got)
	}
}

// TestINV09_PropagateStale_DownstreamInvalidated verifies that PropagateStale
// marks all downstream dependents as STALE when one claim's identity changes.
func TestINV09_PropagateStale_DownstreamInvalidated(t *testing.T) {
	t.Parallel()

	// DAG: primitive-leaves → integral-result → main-theorem
	states := map[string]derive.ClaimStateV2{
		"primitive-leaves": derive.StateGloballyVerified,
		"integral-result":  derive.StateGloballyVerified,
		"main-theorem":     derive.StateGloballyVerified,
		"unrelated-claim":  derive.StateLocallyVerified,
	}
	reverseEdges := map[string][]string{
		"primitive-leaves": {"integral-result"},
		"integral-result":  {"main-theorem"},
	}

	// primitive-leaves identity changes (e.g. primitive data was updated).
	result := derive.PropagateStale(states, reverseEdges, "primitive-leaves")

	for _, id := range []string{"primitive-leaves", "integral-result", "main-theorem"} {
		if result[id] != derive.StateStale {
			t.Errorf("INV-09 VIOLATED: %s should be STALE after upstream change, got %s", id, result[id])
		}
	}
	if result["unrelated-claim"] == derive.StateStale {
		t.Error("INV-09: unrelated-claim must NOT become STALE")
	}
}

// TestINV09_StaleBeatsRelease verifies that STALE takes priority over RELEASED —
// a claim cannot stay RELEASED after its identity closure changes.
func TestINV09_StaleBeatsRelease(t *testing.T) {
	t.Parallel()
	in := derive.DeriveInput{
		ClaimID:             "thm-main",
		CurrentIdentity:     "sha256:new",
		AttestationIdentity: "sha256:old", // identity changed
		Evidence:            derive.EvidencePresent,
		ObligationSet:       derive.ObligationSetPass,
		DepStates:           map[string]derive.ClaimStateV2{},
		RequiredDepStates:   map[string]derive.ClaimStateV2{},
		HasReplay:           true,
		IsReleaseRoot:       true,
		HasSignedManifest:   true,
	}
	got := derive.DeriveClaimState(in)
	if got != derive.StateStale {
		t.Errorf("INV-09 VIOLATED: STALE must take priority over RELEASED, got %s", got)
	}
}
