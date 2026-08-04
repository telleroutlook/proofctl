// Package adversarial contains tests that enforce architecture-level invariants
// (INV-01 through INV-12) for the proofctl v2 kernel.
//
// Tests in this package are the machine-readable enforcement of the invariants
// declared in the Canvas document. A failing test here is a blocking invariant
// violation, not just a quality issue.
//
// INV status:
//   - INV-01: ACTIVE (TestINV01_NoWritablePassField)
//   - INV-06, INV-07, INV-09: PENDING M25 (t.Skip)
//   - Remaining INVs: added as tests in M25
package adversarial

import (
	"reflect"
	"strings"
	"testing"

	v2 "github.com/telleroutlook/proofctl/pkg/protocol/v2"
)

// TestINV01_NoWritablePassField verifies that CheckerOutputV2 does not contain
// any field named Outcome, Assurance, Status, Released, Accepted, or Verified.
//
// INV-01: user input must not contain writable PASS/RELEASED fields.
// A checker cannot assert "accepted" — it can only report obligation verdicts.
//
// This test uses reflection so that adding such a field to CheckerOutputV2
// causes this test to fail, even if the field name differs slightly.
func TestINV01_NoWritablePassField(t *testing.T) {
	t.Parallel()

	// Fields that must NOT exist in the v2 checker output struct.
	forbidden := []string{
		"Outcome",
		"Assurance",
		"Status",
		"Released",
		"Accepted",
		"Verified",
		"Pass",
		"OK", // "OK bool" would allow checker to assert pass directly
	}

	typ := reflect.TypeOf(v2.CheckerOutputV2{})
	for _, name := range forbidden {
		if _, ok := typ.FieldByName(name); ok {
			t.Errorf("INV-01 VIOLATED: CheckerOutputV2 has field %q — "+
				"checkers must not be able to assert acceptance directly; "+
				"use ObligationResults instead", name)
		}
	}

	// Also verify that ObligationResult.Verdict is a typed string, not a boolean.
	// A boolean "OK bool" field would allow the same bypass.
	oblTyp := reflect.TypeOf(v2.ObligationResult{})
	verdictField, ok := oblTyp.FieldByName("Verdict")
	if !ok {
		t.Fatal("INV-01: ObligationResult must have a Verdict field")
	}
	if verdictField.Type.Kind() == reflect.Bool {
		t.Error("INV-01 VIOLATED: ObligationResult.Verdict must not be bool — " +
			"use ObligationVerdict string type so invalid verdicts are rejected")
	}
}

// TestINV01_ObligationVerdictConstants verifies that only "pass" and "fail" are
// valid ObligationVerdict values, and that "accepted", "verified", etc. are not defined.
func TestINV01_ObligationVerdictConstants(t *testing.T) {
	t.Parallel()

	// Valid verdicts
	if v2.VerdictPass != "pass" {
		t.Errorf("VerdictPass must be exactly %q, got %q", "pass", v2.VerdictPass)
	}
	if v2.VerdictFail != "fail" {
		t.Errorf("VerdictFail must be exactly %q, got %q", "fail", v2.VerdictFail)
	}

	// The string representations must not contain "accept", "verif", "release".
	banned := []string{"accept", "verif", "release", "ok", "pass=true"}
	for _, b := range banned {
		if strings.Contains(strings.ToLower(string(v2.VerdictPass)), b) {
			t.Errorf("VerdictPass %q must not contain %q", v2.VerdictPass, b)
		}
	}
}

// TestINV06_ObligationExactSet verifies that the v2 derive logic enforces
// exact-set matching on obligation IDs (no missing, duplicate, or extra IDs).
//
// Status: PENDING M25 — the derive.DeriveClaimState implementation is not
// yet complete. This test documents the requirement and will be activated in M25.
func TestINV06_ObligationExactSet(t *testing.T) {
	t.Skip("INV-06 pending M25: derive.DeriveClaimState obligation exact-set check not yet implemented")

	// When implemented, this test will:
	// 1. Build a ContractV2 with 3 named obligations
	// 2. Feed a CheckerOutputV2 with 2 obligations (missing one) → expect BLOCKED
	// 3. Feed a CheckerOutputV2 with 4 obligations (extra one) → expect BLOCKED
	// 4. Feed a CheckerOutputV2 with a duplicate obligation ID → expect BLOCKED
	// 5. Feed a CheckerOutputV2 with exactly the right 3 IDs, all pass → expect LOCALLY_VERIFIED
}

// TestINV07_PartialEvidenceFailure verifies that when any required evidence causes
// a checker obligation to fail, the entire claim is BLOCKED (not partially accepted).
//
// Status: PENDING M25 — same activation condition as INV-06.
func TestINV07_PartialEvidenceFailure(t *testing.T) {
	t.Skip("INV-07 pending M25: multi-evidence all-must-pass logic not yet implemented")

	// When implemented, this test will:
	// 1. Build a ContractV2 with mode=each and 2 required evidence pieces
	// 2. Run checker: evidence[0] → all obligations pass, evidence[1] → one obligation fails
	// 3. Verify that DeriveClaimState returns BLOCKED (not LOCALLY_VERIFIED)
	// 4. Confirm that no partial-success path exists in the derive logic
}

// TestINV09_StalenessOnIdentityChange verifies that changing any field in the
// identity closure causes PropagateStale to mark the claim and all dependents
// as STALE.
//
// Status: PENDING M25 — PropagateStale is defined but identity.Compute is a stub.
func TestINV09_StalenessOnIdentityChange(t *testing.T) {
	t.Skip("INV-09 pending M25: identity.Compute full implementation required")

	// When implemented, this test will:
	// 1. Compute identity for a claim with known inputs
	// 2. Store an attestation with that identity digest
	// 3. Change one input field (e.g. CheckerIdentityDigest)
	// 4. Recompute identity → different digest
	// 5. Call DeriveClaimState with the new identity → expect STALE
	// 6. Call PropagateStale on a 3-node DAG → all downstream nodes also STALE
}
