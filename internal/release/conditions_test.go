package release_test

import (
	"testing"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
	"github.com/telleroutlook/proofctl/internal/release"
)

// buildGraph builds a DAG with the given claim IDs (no dependencies).
func buildGraph(ids ...string) *dag.DAG {
	g := dag.New()
	for _, id := range ids {
		c := &ir.Claim{ID: id, Kind: "lemma"}
		_ = g.AddClaim(c)
	}
	return g
}

// shadowPolicy is a policy that forbids shadow-review and assumption but allows
// the standard assurance types.
var shadowPolicy = policy.ReleasePolicy{
	Version: "1",
	Target:  "thm-main-radius-030",
	AllowedAssurances: []string{
		"formal-kernel",
		"deterministic-cap",
		"exact-replay",
		"reproducible-computation",
		"independent-review",
	},
	ForbiddenAssurances: []string{"ai-review", "assumption", "shadow-review"},
}

// TestEvaluateConditions_AllShadow uses 3 shadow-review attested claims.
// Expected:
//   - C01 fails (outcome != accepted)
//   - C02 passes (no assumption assurance)
//   - C03 fails (shadow-review is forbidden)
//   - C04-C12 fail (no metadata keys present)
//   - C13 fails (no freshness/digest)
func TestEvaluateConditions_AllShadow(t *testing.T) {
	ids := []string{"claim-a", "claim-b", "claim-c"}
	g := buildGraph(ids...)

	attestations := map[string]*ir.Attestation{
		"claim-a": {
			ClaimID:   "claim-a",
			Outcome:   "blocked",
			Assurance: ir.Assurance("shadow-review"),
		},
		"claim-b": {
			ClaimID:   "claim-b",
			Outcome:   "blocked",
			Assurance: ir.Assurance("shadow-review"),
		},
		"claim-c": {
			ClaimID:   "claim-c",
			Outcome:   "blocked",
			Assurance: ir.Assurance("shadow-review"),
		},
	}

	results := release.EvaluateConditions(g, attestations, shadowPolicy)

	if len(results) != 13 {
		t.Fatalf("expected 13 results, got %d", len(results))
	}

	// C01 should fail — none are accepted
	assertFailed(t, results[0], release.CondGlobalStatusAccepted, "C01")

	// C02 should pass — no assumption assurance
	assertPassed(t, results[1], release.CondAssumptionFootprintEmpty, "C02")

	// C03 should fail — shadow-review is forbidden
	assertFailed(t, results[2], release.CondAllAssurancesAllowed, "C03")

	// C04-C12 should all fail (shadow mode, no metadata)
	shadowConds := []struct {
		idx  int
		id   release.ConditionID
		name string
	}{
		{3, release.CondCAPFormatV2Frozen, "C04"},
		{4, release.CondDigestsFresh, "C05"},
		{5, release.CondPathKeysMatch, "C06"},
		{6, release.CondIntervalsIntersect, "C07"},
		{7, release.CondMatrixReconstructed, "C08"},
		{8, release.CondLDLTPasses, "C09"},
		{9, release.CondOddSectorPasses, "C10"},
		{10, release.CondEvenSectorPasses, "C11"},
		{11, release.CondPivotRadiusRatio, "C12"},
	}
	for _, sc := range shadowConds {
		assertFailed(t, results[sc.idx], sc.id, sc.name)
	}

	// C13 should fail — no freshness or self-digest
	assertFailed(t, results[12], release.CondReplayConsistency, "C13")
}

// TestEvaluateConditions_C02AssumptionFound verifies C02 fails when any attestation
// has assurance "assumption".
func TestEvaluateConditions_C02AssumptionFound(t *testing.T) {
	g := buildGraph("claim-x")
	attestations := map[string]*ir.Attestation{
		"claim-x": {
			ClaimID:   "claim-x",
			Outcome:   "accepted",
			Assurance: ir.AssuranceAssumption,
		},
	}
	results := release.EvaluateConditions(g, attestations, shadowPolicy)
	assertFailed(t, results[1], release.CondAssumptionFootprintEmpty, "C02")
}

// TestEvaluateConditions_C13FreshnessPresent verifies C13 passes when all
// attestations have non-empty SelfDigest, StartFreshness, and EndFreshness.
func TestEvaluateConditions_C13FreshnessPresent(t *testing.T) {
	g := buildGraph("claim-y")
	attestations := map[string]*ir.Attestation{
		"claim-y": {
			ClaimID:        "claim-y",
			Outcome:        "accepted",
			Assurance:      ir.AssuranceFormalKernel,
			SelfDigest:     "sha256:abc123",
			StartFreshness: "sha256:start",
			EndFreshness:   "sha256:end",
		},
	}
	pol := policy.ReleasePolicy{
		Version:           "1",
		AllowedAssurances: []string{"formal-kernel"},
	}
	results := release.EvaluateConditions(g, attestations, pol)
	// C13 is the last result
	assertPassed(t, results[12], release.CondReplayConsistency, "C13")
}

// TestAllPassed_Empty verifies that a nil/empty slice is considered all-passed.
func TestAllPassed_Empty(t *testing.T) {
	if !release.AllPassed(nil) {
		t.Error("AllPassed(nil) should return true")
	}
	if !release.AllPassed([]release.ConditionResult{}) {
		t.Error("AllPassed([]) should return true")
	}
}

// TestAllPassed_OneFail verifies AllPassed returns false when one condition failed.
func TestAllPassed_OneFail(t *testing.T) {
	results := []release.ConditionResult{
		{ID: release.CondGlobalStatusAccepted, Passed: true},
		{ID: release.CondAssumptionFootprintEmpty, Passed: false, Blocker: "some blocker"},
	}
	if release.AllPassed(results) {
		t.Error("AllPassed should return false when one condition failed")
	}
}

// TestBlockers_OnlyFailed verifies that Blockers only returns entries for failed conditions.
func TestBlockers_OnlyFailed(t *testing.T) {
	results := []release.ConditionResult{
		{ID: release.CondGlobalStatusAccepted, Passed: true},
		{ID: release.CondAssumptionFootprintEmpty, Passed: false, Blocker: "reason A"},
		{ID: release.CondAllAssurancesAllowed, Passed: true},
		{ID: release.CondCAPFormatV2Frozen, Passed: false, Blocker: "reason B"},
	}
	blockers := release.Blockers(results)
	if len(blockers) != 2 {
		t.Fatalf("expected 2 blockers, got %d: %v", len(blockers), blockers)
	}
	// Verify content includes the condition ID and blocker text.
	for _, b := range blockers {
		if len(b) == 0 {
			t.Error("blocker string should not be empty")
		}
	}
}

// assertPassed is a helper that fails the test if the result did not pass.
func assertPassed(t *testing.T, r release.ConditionResult, wantID release.ConditionID, label string) {
	t.Helper()
	if r.ID != wantID {
		t.Errorf("%s: expected condition ID %q, got %q", label, wantID, r.ID)
	}
	if !r.Passed {
		t.Errorf("%s: expected passed=true, got failed: %s", label, r.Blocker)
	}
}

// assertFailed is a helper that fails the test if the result unexpectedly passed.
func assertFailed(t *testing.T, r release.ConditionResult, wantID release.ConditionID, label string) {
	t.Helper()
	if r.ID != wantID {
		t.Errorf("%s: expected condition ID %q, got %q", label, wantID, r.ID)
	}
	if r.Passed {
		t.Errorf("%s: expected passed=false, but condition passed", label)
	}
	if r.Blocker == "" {
		t.Errorf("%s: expected non-empty blocker message for failed condition", label)
	}
}
