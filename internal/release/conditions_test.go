package release_test

import (
	"strings"
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

// basePolicy is a policy with no required_metadata_keys (domain-agnostic).
var basePolicy = policy.ReleasePolicy{
	Version: "1",
	Target:  "thm-main",
	AllowedAssurances: []string{
		"formal-kernel",
		"deterministic-cap",
		"exact-replay",
		"reproducible-computation",
		"independent-review",
	},
	ForbiddenAssurances: []string{"ai-review", "assumption", "shadow-review"},
}

// capPolicy adds weil-style required_metadata_keys to basePolicy.
var capPolicy = policy.ReleasePolicy{
	Version:             "1",
	Target:              "thm-main-radius-030",
	AllowedAssurances:   basePolicy.AllowedAssurances,
	ForbiddenAssurances: basePolicy.ForbiddenAssurances,
	RequiredMetadataKeys: []string{
		"cap_format_version",
		"ldlt_passes",
		"odd_sector_passes",
	},
}

// TestEvaluateConditions_NoMetadataKeys verifies that a policy with no
// required_metadata_keys produces exactly 4 universal conditions.
func TestEvaluateConditions_NoMetadataKeys(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:        "c1",
			Outcome:        "accepted",
			Assurance:      ir.AssuranceFormalKernel,
			SelfDigest:     "sha256:abc",
			StartFreshness: "sha256:s",
			EndFreshness:   "sha256:e",
		},
	}
	results := release.EvaluateConditions(g, atts, basePolicy)
	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}
	for _, r := range results {
		if !r.Passed {
			t.Errorf("condition %s failed unexpectedly: %s", r.ID, r.Blocker)
		}
	}
}

// TestEvaluateConditions_WithMetadataKeys verifies that required_metadata_keys
// in the policy produce additional conditions beyond the 4 universal ones.
func TestEvaluateConditions_WithMetadataKeys(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:        "c1",
			Outcome:        "accepted",
			Assurance:      ir.AssuranceFormalKernel,
			SelfDigest:     "sha256:abc",
			StartFreshness: "sha256:s",
			EndFreshness:   "sha256:e",
			Metadata: map[string]string{
				"cap_format_version": "2.0",
				"ldlt_passes":        "true",
				"odd_sector_passes":  "true",
			},
		},
	}
	results := release.EvaluateConditions(g, atts, capPolicy)
	// 4 universal + 3 metadata = 7
	if len(results) != 7 {
		t.Fatalf("expected 7 results, got %d", len(results))
	}
	for _, r := range results {
		if !r.Passed {
			t.Errorf("condition %s failed unexpectedly: %s", r.ID, r.Blocker)
		}
	}
	// Verify meta condition IDs are correctly named.
	if got := string(results[4].ID); got != "meta:cap_format_version" {
		t.Errorf("results[4].ID = %q, want %q", got, "meta:cap_format_version")
	}
}

// TestEvaluateConditions_MetadataKeyMissing verifies that a missing metadata key
// produces a failed meta condition with a descriptive blocker.
func TestEvaluateConditions_MetadataKeyMissing(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:        "c1",
			Outcome:        "accepted",
			Assurance:      ir.AssuranceFormalKernel,
			SelfDigest:     "sha256:abc",
			StartFreshness: "sha256:s",
			EndFreshness:   "sha256:e",
			// No metadata at all.
		},
	}
	results := release.EvaluateConditions(g, atts, capPolicy)
	if len(results) != 7 {
		t.Fatalf("expected 7 results, got %d", len(results))
	}
	// All 3 meta conditions should fail.
	for _, r := range results[4:] {
		if r.Passed {
			t.Errorf("meta condition %s should have failed", r.ID)
		}
		if r.Blocker == "" {
			t.Errorf("meta condition %s: blocker should not be empty", r.ID)
		}
	}
}

// TestEvaluateConditions_C01GlobalFail verifies C01 fails when a claim is not accepted.
func TestEvaluateConditions_C01GlobalFail(t *testing.T) {
	g := buildGraph("claim-a")
	atts := map[string]*ir.Attestation{
		"claim-a": {ClaimID: "claim-a", Outcome: "blocked", Assurance: "shadow-review"},
	}
	results := release.EvaluateConditions(g, atts, basePolicy)
	assertFailed(t, results[0], release.CondGlobalStatusAccepted, "C01")
}

// TestEvaluateConditions_C02AssumptionFound verifies C02 fails when any attestation
// uses assurance "assumption".
func TestEvaluateConditions_C02AssumptionFound(t *testing.T) {
	g := buildGraph("claim-x")
	atts := map[string]*ir.Attestation{
		"claim-x": {ClaimID: "claim-x", Outcome: "accepted", Assurance: ir.AssuranceAssumption},
	}
	results := release.EvaluateConditions(g, atts, basePolicy)
	assertFailed(t, results[1], release.CondAssumptionFootprintEmpty, "C02")
}

// TestEvaluateConditions_C04ReplayPresent verifies C04 passes when freshness fields are set.
func TestEvaluateConditions_C04ReplayPresent(t *testing.T) {
	g := buildGraph("claim-y")
	atts := map[string]*ir.Attestation{
		"claim-y": {
			ClaimID:        "claim-y",
			Outcome:        "accepted",
			Assurance:      ir.AssuranceFormalKernel,
			SelfDigest:     "sha256:abc123",
			StartFreshness: "sha256:start",
			EndFreshness:   "sha256:end",
		},
	}
	pol := policy.ReleasePolicy{Version: "1", AllowedAssurances: []string{"formal-kernel"}}
	results := release.EvaluateConditions(g, atts, pol)
	assertPassed(t, results[3], release.CondReplayConsistency, "C04")
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
		{ID: "meta:cap_format_version", Passed: false, Blocker: "reason B"},
	}
	blockers := release.Blockers(results)
	if len(blockers) != 2 {
		t.Fatalf("expected 2 blockers, got %d: %v", len(blockers), blockers)
	}
	for _, b := range blockers {
		if len(b) == 0 {
			t.Error("blocker string should not be empty")
		}
	}
}

// TestBlockers_ContainID verifies that blocker strings include the condition ID.
func TestBlockers_ContainID(t *testing.T) {
	results := []release.ConditionResult{
		{ID: release.CondAssumptionFootprintEmpty, Passed: false, Blocker: "reason A"},
	}
	blockers := release.Blockers(results)
	if len(blockers) != 1 {
		t.Fatalf("expected 1 blocker, got %d", len(blockers))
	}
	if !strings.Contains(blockers[0], string(release.CondAssumptionFootprintEmpty)) {
		t.Errorf("blocker %q does not contain condition ID %q", blockers[0], release.CondAssumptionFootprintEmpty)
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
