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
	results := release.EvaluateConditions(g, atts, basePolicy, "")
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
	results := release.EvaluateConditions(g, atts, capPolicy, "")
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
	results := release.EvaluateConditions(g, atts, capPolicy, "")
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
	results := release.EvaluateConditions(g, atts, basePolicy, "")
	assertFailed(t, results[0], release.CondGlobalStatusAccepted, "C01")
}

// TestEvaluateConditions_C02AssumptionFound verifies C02 fails when any attestation
// uses assurance "assumption".
func TestEvaluateConditions_C02AssumptionFound(t *testing.T) {
	g := buildGraph("claim-x")
	atts := map[string]*ir.Attestation{
		"claim-x": {ClaimID: "claim-x", Outcome: "accepted", Assurance: ir.AssuranceAssumption},
	}
	results := release.EvaluateConditions(g, atts, basePolicy, "")
	assertFailed(t, results[1], release.CondAssumptionFootprintEmpty, "C02")
}

// TestEvaluateConditions_C03ForbiddenAssurance verifies C03 fails when a forbidden assurance is used.
func TestEvaluateConditions_C03ForbiddenAssurance(t *testing.T) {
	g := buildGraph("claim-f")
	atts := map[string]*ir.Attestation{
		"claim-f": {ClaimID: "claim-f", Outcome: "accepted", Assurance: ir.AssuranceAIReview},
	}
	results := release.EvaluateConditions(g, atts, basePolicy, "")
	assertFailed(t, results[2], release.CondAllAssurancesAllowed, "C03")
}

// TestEvaluateConditions_C03NotInAllowedList verifies C03 fails when assurance is not in the allowed list.
func TestEvaluateConditions_C03NotInAllowedList(t *testing.T) {
	g := buildGraph("claim-x")
	pol := policy.ReleasePolicy{
		AllowedAssurances: []string{"formal-kernel"},
	}
	atts := map[string]*ir.Attestation{
		"claim-x": {ClaimID: "claim-x", Outcome: "accepted", Assurance: ir.AssuranceIndependentReview},
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	assertFailed(t, results[2], release.CondAllAssurancesAllowed, "C03")
}

// TestEvaluateConditions_C03EmptyAssuranceSkipped verifies C03 skips attestations with empty assurance.
func TestEvaluateConditions_C03EmptyAssuranceSkipped(t *testing.T) {
	g := buildGraph("claim-v2")
	pol := policy.ReleasePolicy{
		AllowedAssurances: []string{"formal-kernel"},
	}
	atts := map[string]*ir.Attestation{
		"claim-v2": {ClaimID: "claim-v2", Outcome: "accepted", Assurance: ""},
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	assertPassed(t, results[2], release.CondAllAssurancesAllowed, "C03")
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
	results := release.EvaluateConditions(g, atts, pol, "")
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

// TestC06AllowedMetadataValues_Pass verifies that C06 passes when all metadata values
// are in the allowed set.
func TestC06AllowedMetadataValues_Pass(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:        "c1",
			Outcome:        "accepted",
			Assurance:      ir.AssuranceFormalKernel,
			SelfDigest:     "sha256:abc",
			StartFreshness: "2026-08-04",
			EndFreshness:   "2026-08-04",
			Metadata:       map[string]string{"remainder_type": "gl_bernstein_ellipse"},
		},
	}
	pol := policy.ReleasePolicy{
		Version:           "1",
		AllowedAssurances: []string{"formal-kernel"},
		AllowedMetadataValues: map[string][]string{
			"remainder_type": {"gl_bernstein_ellipse", "legendre_tail", "zero"},
		},
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	// 4 universal + 1 C06
	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}
	c06 := results[4]
	if c06.ID != release.CondMetadataValues {
		t.Fatalf("results[4].ID = %q, want %q", c06.ID, release.CondMetadataValues)
	}
	if !c06.Passed {
		t.Errorf("C06 should pass, got blocker: %s", c06.Blocker)
	}
}

// TestC06AllowedMetadataValues_Fail verifies that C06 fails when a metadata value
// is not in the allowed set.
func TestC06AllowedMetadataValues_Fail(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:    "c1",
			Outcome:    "accepted",
			Assurance:  ir.AssuranceFormalKernel,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-04", EndFreshness: "2026-08-04",
			Metadata: map[string]string{"remainder_type": "gl_self_convergence"},
		},
	}
	pol := policy.ReleasePolicy{
		Version:           "1",
		AllowedAssurances: []string{"formal-kernel"},
		AllowedMetadataValues: map[string][]string{
			"remainder_type": {"gl_bernstein_ellipse", "legendre_tail", "zero"},
		},
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	c06 := results[4]
	if c06.Passed {
		t.Error("C06 should fail when value is not in allowed set")
	}
	if !strings.Contains(c06.Blocker, "gl_self_convergence") {
		t.Errorf("blocker should mention the bad value, got: %s", c06.Blocker)
	}
}

// TestC07ConditionalMetadata_NotTriggered verifies that C07 passes when the trigger
// key is absent (condition not activated).
func TestC07ConditionalMetadata_NotTriggered(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:    "c1",
			Outcome:    "accepted",
			Assurance:  ir.AssuranceFormalKernel,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-04", EndFreshness: "2026-08-04",
			Metadata: map[string]string{"other_key": "val"},
		},
	}
	pol := policy.ReleasePolicy{
		Version:                 "1",
		AllowedAssurances:       []string{"formal-kernel"},
		ConditionalMetadataKeys: map[string]string{"kernel_branch": "drpp_bound_proof"},
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	c07 := results[4]
	if c07.ID != release.CondConditionalMetadata {
		t.Fatalf("results[4].ID = %q, want %q", c07.ID, release.CondConditionalMetadata)
	}
	if !c07.Passed {
		t.Errorf("C07 should pass when trigger is absent, got: %s", c07.Blocker)
	}
}

// TestC07ConditionalMetadata_Triggered_Missing verifies that C07 fails when the trigger
// key is present but the required key is absent.
func TestC07ConditionalMetadata_Triggered_Missing(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:    "c1",
			Outcome:    "accepted",
			Assurance:  ir.AssuranceFormalKernel,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-04", EndFreshness: "2026-08-04",
			Metadata: map[string]string{"kernel_branch": "odd_sector"},
		},
	}
	pol := policy.ReleasePolicy{
		Version:                 "1",
		AllowedAssurances:       []string{"formal-kernel"},
		ConditionalMetadataKeys: map[string]string{"kernel_branch": "drpp_bound_proof"},
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	c07 := results[4]
	if c07.Passed {
		t.Error("C07 should fail when trigger is present but required key is absent")
	}
	if !strings.Contains(c07.Blocker, "drpp_bound_proof") {
		t.Errorf("blocker should mention the missing required key, got: %s", c07.Blocker)
	}
}

// TestC07ConditionalMetadata_Triggered_Present verifies that C07 passes when both
// the trigger key and required key are present.
func TestC07ConditionalMetadata_Triggered_Present(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:    "c1",
			Outcome:    "accepted",
			Assurance:  ir.AssuranceFormalKernel,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-04", EndFreshness: "2026-08-04",
			Metadata: map[string]string{
				"kernel_branch":    "odd_sector",
				"drpp_bound_proof": "certified",
			},
		},
	}
	pol := policy.ReleasePolicy{
		Version:                 "1",
		AllowedAssurances:       []string{"formal-kernel"},
		ConditionalMetadataKeys: map[string]string{"kernel_branch": "drpp_bound_proof"},
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	c07 := results[4]
	if !c07.Passed {
		t.Errorf("C07 should pass when required key is present, got: %s", c07.Blocker)
	}
}

// TestC08ReplayMode_Pass verifies that C08 passes when all attestations have the
// required replay_mode.
func TestC08ReplayMode_Pass(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:    "c1",
			Outcome:    "accepted",
			Assurance:  ir.AssuranceExactReplay,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-04", EndFreshness: "2026-08-04",
			ReplayMode: "from_scratch",
		},
	}
	pol := policy.ReleasePolicy{
		Version:            "1",
		AllowedAssurances:  []string{"exact-replay"},
		RequiredReplayMode: "from_scratch",
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	c08 := results[4]
	if c08.ID != release.CondReplayMode {
		t.Fatalf("results[4].ID = %q, want %q", c08.ID, release.CondReplayMode)
	}
	if !c08.Passed {
		t.Errorf("C08 should pass, got: %s", c08.Blocker)
	}
}

// TestC08ReplayMode_Fail verifies that C08 fails when an attestation has the wrong
// replay_mode.
func TestC08ReplayMode_Fail(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:    "c1",
			Outcome:    "accepted",
			Assurance:  ir.AssuranceExactReplay,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-04", EndFreshness: "2026-08-04",
			ReplayMode: "self_consistency",
		},
	}
	pol := policy.ReleasePolicy{
		Version:            "1",
		AllowedAssurances:  []string{"exact-replay"},
		RequiredReplayMode: "from_scratch",
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	c08 := results[4]
	if c08.Passed {
		t.Error("C08 should fail when replay_mode does not match required value")
	}
	if !strings.Contains(c08.Blocker, "self_consistency") {
		t.Errorf("blocker should mention the actual replay_mode, got: %s", c08.Blocker)
	}
}

// TestC08ReplayMode_LegacyExempt verifies that C08 exempts attestations with an
// empty replay_mode (written before the field was introduced).
func TestC08ReplayMode_LegacyExempt(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:    "c1",
			Outcome:    "accepted",
			Assurance:  ir.AssuranceExactReplay,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-04", EndFreshness: "2026-08-04",
			// ReplayMode deliberately empty (legacy attestation)
		},
	}
	pol := policy.ReleasePolicy{
		Version:            "1",
		AllowedAssurances:  []string{"exact-replay"},
		RequiredReplayMode: "from_scratch",
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	c08 := results[4]
	if !c08.Passed {
		t.Errorf("C08 should exempt legacy attestations with empty replay_mode, got: %s", c08.Blocker)
	}
}

// ── C09: no native runtime ────────────────────────────────────────────────────

func TestC09_NoNativeRuntime_Pass(t *testing.T) {
	t.Parallel()
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:        "c1",
			Outcome:        "accepted",
			Assurance:      ir.AssuranceDeterministicCAP,
			SelfDigest:     "sha256:abc",
			StartFreshness: "2026-08-04",
			EndFreshness:   "2026-08-04",
			Checker: ir.CheckerIdentity{
				ID:      "checker-v1",
				Runtime: ir.Runtime{Kind: "oci"},
			},
		},
	}
	pol := policy.ReleasePolicy{
		Version:           "2",
		AllowedAssurances: []string{"deterministic-cap"},
		ForbiddenRuntimes: []string{"native", "native-dev"},
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	var c09 *release.ConditionResult
	for i := range results {
		if results[i].ID == release.CondNoNativeRuntime {
			c09 = &results[i]
			break
		}
	}
	if c09 == nil {
		t.Fatal("C09 condition not found in results")
	}
	if !c09.Passed {
		t.Errorf("C09 should pass for oci runtime, got blocker: %s", c09.Blocker)
	}
}

func TestC09_NoNativeRuntime_Fail(t *testing.T) {
	t.Parallel()
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:        "c1",
			Outcome:        "accepted",
			Assurance:      ir.AssuranceDeterministicCAP,
			SelfDigest:     "sha256:abc",
			StartFreshness: "2026-08-04",
			EndFreshness:   "2026-08-04",
			Checker: ir.CheckerIdentity{
				ID:      "checker-native",
				Runtime: ir.Runtime{Kind: "native"}, // forbidden (INV-10)
			},
		},
	}
	pol := policy.ReleasePolicy{
		Version:           "2",
		AllowedAssurances: []string{"deterministic-cap"},
		ForbiddenRuntimes: []string{"native", "native-dev"},
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	var c09 *release.ConditionResult
	for i := range results {
		if results[i].ID == release.CondNoNativeRuntime {
			c09 = &results[i]
			break
		}
	}
	if c09 == nil {
		t.Fatal("C09 condition not found in results")
	}
	if c09.Passed {
		t.Error("C09 should fail when native runtime is used (INV-10)")
	}
	if c09.Blocker == "" {
		t.Error("C09 blocker message must not be empty")
	}
}

func TestC09_NoNativeRuntime_NotActivatedWhenPolicyEmpty(t *testing.T) {
	t.Parallel()
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID:        "c1",
			Outcome:        "accepted",
			Assurance:      ir.AssuranceDeterministicCAP,
			SelfDigest:     "sha256:abc",
			StartFreshness: "2026-08-04",
			EndFreshness:   "2026-08-04",
			Checker: ir.CheckerIdentity{
				ID:      "checker-native",
				Runtime: ir.Runtime{Kind: "native"},
			},
		},
	}
	// No ForbiddenRuntimes set → C09 must NOT be evaluated.
	pol := policy.ReleasePolicy{
		Version:           "1",
		AllowedAssurances: []string{"deterministic-cap"},
	}
	results := release.EvaluateConditions(g, atts, pol, "")
	for _, r := range results {
		if r.ID == release.CondNoNativeRuntime {
			t.Error("C09 must not appear in results when ForbiddenRuntimes is empty")
		}
	}
}

// ── C10: no copy-only generator (Weil FP-0.35 pilot regression) ───────────────

func TestC10_CopyOnlyGenerator_Fail(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID: "c1", Outcome: "accepted", Assurance: ir.AssuranceReproducibleComputation,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-06", EndFreshness: "2026-08-06",
			ReplayMode: "from_scratch",
			Metadata: map[string]string{
				"generator_cmds": "python3 -c \"import shutil; shutil.copy('certs/thm-fp-035.json', '{cert}')\"",
			},
		},
	}
	pol := policy.ReleasePolicy{Version: "1", AllowedAssurances: []string{"reproducible-computation"}, ForbidCopyOnlyGenerators: true}
	results := release.EvaluateConditions(g, atts, pol, "")
	var c10 *release.ConditionResult
	for i := range results {
		if results[i].ID == release.CondNoCopyOnlyGenerator {
			c10 = &results[i]
		}
	}
	if c10 == nil {
		t.Fatal("C10 not evaluated when ForbidCopyOnlyGenerators=true")
	}
	if c10.Passed {
		t.Error("C10 must BLOCK a copy-only generator marked from_scratch (Weil FP-0.35 regression)")
	}
	if !strings.Contains(c10.Blocker, "copy-only") {
		t.Errorf("blocker should mention copy-only, got: %s", c10.Blocker)
	}
}

func TestC10_RealGenerator_Pass(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID: "c1", Outcome: "accepted", Assurance: ir.AssuranceReproducibleComputation,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-06", EndFreshness: "2026-08-06",
			ReplayMode: "from_scratch",
			Metadata: map[string]string{
				"generator_cmds": "python3 checker/fp035/recompute_schur.py --sector even --out {cert}",
			},
		},
	}
	pol := policy.ReleasePolicy{Version: "1", AllowedAssurances: []string{"reproducible-computation"}, ForbidCopyOnlyGenerators: true}
	results := release.EvaluateConditions(g, atts, pol, "")
	for i := range results {
		if results[i].ID == release.CondNoCopyOnlyGenerator && !results[i].Passed {
			t.Errorf("C10 must PASS a genuine recomputation generator, got: %s", results[i].Blocker)
		}
	}
}

func TestC10_NotActivatedWhenPolicyFalse(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID: "c1", Outcome: "accepted", Assurance: ir.AssuranceReproducibleComputation,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-06", EndFreshness: "2026-08-06",
			ReplayMode: "from_scratch",
			Metadata:   map[string]string{"generator_cmds": "cp certs/x.json {cert}"},
		},
	}
	pol := policy.ReleasePolicy{Version: "1", AllowedAssurances: []string{"reproducible-computation"}}
	results := release.EvaluateConditions(g, atts, pol, "")
	for i := range results {
		if results[i].ID == release.CondNoCopyOnlyGenerator {
			t.Error("C10 must not be evaluated when ForbidCopyOnlyGenerators=false")
		}
	}
}

func TestC10_SelfConsistencyExempt(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID: "c1", Outcome: "accepted", Assurance: ir.AssuranceIndependentReview,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-06", EndFreshness: "2026-08-06",
			ReplayMode: "self_consistency",
			Metadata:   map[string]string{"generator_cmds": "cp certs/x.json {cert}"},
		},
	}
	pol := policy.ReleasePolicy{Version: "1", AllowedAssurances: []string{"independent-review"}, ForbidCopyOnlyGenerators: true}
	results := release.EvaluateConditions(g, atts, pol, "")
	for i := range results {
		if results[i].ID == release.CondNoCopyOnlyGenerator && !results[i].Passed {
			t.Errorf("C10 should exempt self_consistency attestations, got: %s", results[i].Blocker)
		}
	}
}

// ── C11: checker mutation coverage (honest-but-incomplete checker gap) ─────────

func TestC11_NoMutationCoverage_Fail(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID: "c1", Outcome: "accepted", Assurance: ir.AssuranceReproducibleComputation,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-07", EndFreshness: "2026-08-07",
			ReplayMode: "from_scratch",
			Metadata:   map[string]string{}, // no mutation evidence
		},
	}
	pol := policy.ReleasePolicy{Version: "1", AllowedAssurances: []string{"reproducible-computation"}, RequireCheckerMutationCoverage: true}
	results := release.EvaluateConditions(g, atts, pol, "")
	var c11 *release.ConditionResult
	for i := range results {
		if results[i].ID == release.CondCheckerMutationCoverage {
			c11 = &results[i]
		}
	}
	if c11 == nil {
		t.Fatal("C11 not evaluated when RequireCheckerMutationCoverage=true")
	}
	if c11.Passed {
		t.Error("C11 must BLOCK an attestation with no mutation coverage evidence")
	}
}

func TestC11_PartialKillRate_Fail(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID: "c1", Outcome: "accepted", Assurance: ir.AssuranceReproducibleComputation,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-07", EndFreshness: "2026-08-07",
			ReplayMode: "from_scratch",
			Metadata:   map[string]string{"mutation_kill_rate": "90%", "mutation_catalog_digest": "sha256:cat"},
		},
	}
	pol := policy.ReleasePolicy{Version: "1", AllowedAssurances: []string{"reproducible-computation"}, RequireCheckerMutationCoverage: true}
	results := release.EvaluateConditions(g, atts, pol, "")
	for i := range results {
		if results[i].ID == release.CondCheckerMutationCoverage && results[i].Passed {
			t.Error("C11 must BLOCK a kill rate below 100%")
		}
	}
}

func TestC11_FullCoverage_Pass(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID: "c1", Outcome: "accepted", Assurance: ir.AssuranceReproducibleComputation,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-07", EndFreshness: "2026-08-07",
			ReplayMode: "from_scratch",
			Metadata:   map[string]string{"mutation_kill_rate": "100%", "mutation_catalog_digest": "sha256:cat123"},
		},
	}
	pol := policy.ReleasePolicy{Version: "1", AllowedAssurances: []string{"reproducible-computation"}, RequireCheckerMutationCoverage: true}
	results := release.EvaluateConditions(g, atts, pol, "")
	for i := range results {
		if results[i].ID == release.CondCheckerMutationCoverage && !results[i].Passed {
			t.Errorf("C11 must PASS full coverage, got: %s", results[i].Blocker)
		}
	}
}

func TestC11_EmptyCatalogDigest_Fail(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID: "c1", Outcome: "accepted", Assurance: ir.AssuranceReproducibleComputation,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-07", EndFreshness: "2026-08-07",
			ReplayMode: "from_scratch",
			Metadata:   map[string]string{"mutation_kill_rate": "100%", "mutation_catalog_digest": ""},
		},
	}
	pol := policy.ReleasePolicy{Version: "1", AllowedAssurances: []string{"reproducible-computation"}, RequireCheckerMutationCoverage: true}
	results := release.EvaluateConditions(g, atts, pol, "")
	for i := range results {
		if results[i].ID == release.CondCheckerMutationCoverage && results[i].Passed {
			t.Error("C11 must BLOCK 100%% kill rate with empty catalog digest (unauditable)")
		}
	}
}

func TestC11_NotActivatedWhenPolicyFalse(t *testing.T) {
	g := buildGraph("c1")
	atts := map[string]*ir.Attestation{
		"c1": {
			ClaimID: "c1", Outcome: "accepted", Assurance: ir.AssuranceReproducibleComputation,
			SelfDigest: "sha256:abc", StartFreshness: "2026-08-07", EndFreshness: "2026-08-07",
			ReplayMode: "from_scratch",
			Metadata:   map[string]string{},
		},
	}
	pol := policy.ReleasePolicy{Version: "1", AllowedAssurances: []string{"reproducible-computation"}}
	results := release.EvaluateConditions(g, atts, pol, "")
	for i := range results {
		if results[i].ID == release.CondCheckerMutationCoverage {
			t.Error("C11 must not be evaluated when RequireCheckerMutationCoverage=false")
		}
	}
}
