package derive_test

import (
	"testing"

	"github.com/telleroutlook/proofctl/internal/kernel/derive"
)

// baseInput returns a minimal DeriveInput that should produce LOCALLY_VERIFIED
// when obligations pass and there are no deps.
func baseVerifiedInput() derive.DeriveInput {
	return derive.DeriveInput{
		ClaimID:             "thm-main",
		CurrentIdentity:     "sha256:aaaa",
		AttestationIdentity: "sha256:aaaa",
		Evidence:            derive.EvidencePresent,
		ObligationSet:       derive.ObligationSetPass,
		DepStates:           map[string]derive.ClaimStateV2{},
		RequiredDepStates:   map[string]derive.ClaimStateV2{},
	}
}

// ── Basic state transitions ───────────────────────────────────────────────────

func TestDeriveClaimState_Open_NoEvidence(t *testing.T) {
	t.Parallel()
	in := derive.DeriveInput{
		ClaimID:         "c1",
		CurrentIdentity: "sha256:1111",
		Evidence:        derive.EvidenceAbsent,
		ObligationSet:   derive.ObligationSetAbsent,
	}
	got := derive.DeriveClaimState(in)
	if got != derive.StateOpen {
		t.Errorf("want OPEN, got %s", got)
	}
}

func TestDeriveClaimState_Open_PartialEvidence(t *testing.T) {
	t.Parallel()
	in := derive.DeriveInput{
		ClaimID:         "c1",
		CurrentIdentity: "sha256:1111",
		Evidence:        derive.EvidencePartial,
		ObligationSet:   derive.ObligationSetAbsent,
	}
	got := derive.DeriveClaimState(in)
	if got != derive.StateOpen {
		t.Errorf("want OPEN, got %s", got)
	}
}

func TestDeriveClaimState_Candidate(t *testing.T) {
	t.Parallel()
	in := derive.DeriveInput{
		ClaimID:         "c1",
		CurrentIdentity: "sha256:1111",
		Evidence:        derive.EvidencePresent,
		ObligationSet:   derive.ObligationSetAbsent,
	}
	got := derive.DeriveClaimState(in)
	if got != derive.StateCandidate {
		t.Errorf("want CANDIDATE, got %s", got)
	}
}

func TestDeriveClaimState_LocallyVerified(t *testing.T) {
	t.Parallel()
	// A claim with one dep that hasn't reached required state stays LOCALLY_VERIFIED.
	in := baseVerifiedInput()
	in.DepStates = map[string]derive.ClaimStateV2{"dep1": derive.StateLocallyVerified}
	in.RequiredDepStates = map[string]derive.ClaimStateV2{"dep1": derive.StateGloballyVerified}
	got := derive.DeriveClaimState(in)
	if got != derive.StateLocallyVerified {
		t.Errorf("want LOCALLY_VERIFIED, got %s", got)
	}
}

func TestDeriveClaimState_GloballyVerified(t *testing.T) {
	t.Parallel()
	in := baseVerifiedInput()
	in.DepStates = map[string]derive.ClaimStateV2{"dep1": derive.StateGloballyVerified}
	in.RequiredDepStates = map[string]derive.ClaimStateV2{"dep1": derive.StateGloballyVerified}
	got := derive.DeriveClaimState(in)
	if got != derive.StateGloballyVerified {
		t.Errorf("want GLOBALLY_VERIFIED, got %s", got)
	}
}

func TestDeriveClaimState_Reproducible(t *testing.T) {
	t.Parallel()
	in := baseVerifiedInput()
	in.HasReplay = true
	got := derive.DeriveClaimState(in)
	if got != derive.StateReproducible {
		t.Errorf("want REPRODUCIBLE, got %s", got)
	}
}

func TestDeriveClaimState_Released(t *testing.T) {
	t.Parallel()
	in := baseVerifiedInput()
	in.HasReplay = true
	in.IsReleaseRoot = true
	in.HasSignedManifest = true
	got := derive.DeriveClaimState(in)
	if got != derive.StateReleased {
		t.Errorf("want RELEASED, got %s", got)
	}
}

func TestDeriveClaimState_Released_NoReplayRequired(t *testing.T) {
	t.Parallel()
	// A release root without replay can still reach RELEASED if manifest is signed.
	in := baseVerifiedInput()
	in.IsReleaseRoot = true
	in.HasSignedManifest = true
	got := derive.DeriveClaimState(in)
	if got != derive.StateReleased {
		t.Errorf("want RELEASED, got %s", got)
	}
}

// ── Blocking rules ────────────────────────────────────────────────────────────

// INV-09: mismatch between stored and current identity → STALE.
func TestDeriveClaimState_Stale(t *testing.T) {
	t.Parallel()
	in := baseVerifiedInput()
	in.AttestationIdentity = "sha256:old-identity"
	in.CurrentIdentity = "sha256:new-identity"
	got := derive.DeriveClaimState(in)
	if got != derive.StateStale {
		t.Errorf("want STALE (INV-09), got %s", got)
	}
}

// INV-09: STALE takes priority over everything else.
func TestDeriveClaimState_Stale_TakesPriority(t *testing.T) {
	t.Parallel()
	in := baseVerifiedInput()
	in.AttestationIdentity = "sha256:old"
	in.CurrentIdentity = "sha256:new"
	in.ObligationSet = derive.ObligationSetFail // would be BLOCKED without staleness
	got := derive.DeriveClaimState(in)
	if got != derive.StateStale {
		t.Errorf("STALE must take priority over BLOCKED, got %s", got)
	}
}

// INV-07: any failing obligation → BLOCKED.
func TestDeriveClaimState_Blocked_ObligationFail(t *testing.T) {
	t.Parallel()
	in := baseVerifiedInput()
	in.ObligationSet = derive.ObligationSetFail
	got := derive.DeriveClaimState(in)
	if got != derive.StateBlocked {
		t.Errorf("want BLOCKED (INV-07: obligation fail), got %s", got)
	}
}

// INV-06: obligation ID set mismatch → BLOCKED.
func TestDeriveClaimState_Blocked_ObligationMismatch(t *testing.T) {
	t.Parallel()
	in := baseVerifiedInput()
	in.ObligationSet = derive.ObligationSetMismatch
	got := derive.DeriveClaimState(in)
	if got != derive.StateBlocked {
		t.Errorf("want BLOCKED (INV-06: obligation set mismatch), got %s", got)
	}
}

// INV-08: blocked dep → BLOCKED.
func TestDeriveClaimState_Blocked_DepBlocked(t *testing.T) {
	t.Parallel()
	in := baseVerifiedInput()
	in.DepStates = map[string]derive.ClaimStateV2{"dep1": derive.StateBlocked}
	in.RequiredDepStates = map[string]derive.ClaimStateV2{"dep1": derive.StateGloballyVerified}
	got := derive.DeriveClaimState(in)
	if got != derive.StateBlocked {
		t.Errorf("want BLOCKED (INV-08: blocked dep), got %s", got)
	}
}

// INV-08: dep not at required state → LOCALLY_VERIFIED (obligations pass locally,
// but deps not ready prevents upgrade to GLOBALLY_VERIFIED).
func TestDeriveClaimState_LocallyVerified_DepBelowRequired(t *testing.T) {
	t.Parallel()
	in := baseVerifiedInput()
	in.DepStates = map[string]derive.ClaimStateV2{"dep1": derive.StateLocallyVerified}
	in.RequiredDepStates = map[string]derive.ClaimStateV2{"dep1": derive.StateGloballyVerified}
	got := derive.DeriveClaimState(in)
	if got != derive.StateLocallyVerified {
		t.Errorf("want LOCALLY_VERIFIED (dep below required state stops GV upgrade, INV-08), got %s", got)
	}
}

// ── Attestation identity absent ───────────────────────────────────────────────

func TestDeriveClaimState_NoAttestation_Candidate(t *testing.T) {
	t.Parallel()
	// No attestation means AttestationIdentity is empty → not STALE, proceeds normally.
	in := derive.DeriveInput{
		ClaimID:             "c1",
		CurrentIdentity:     "sha256:1111",
		AttestationIdentity: "", // no stored attestation
		Evidence:            derive.EvidencePresent,
		ObligationSet:       derive.ObligationSetAbsent,
	}
	got := derive.DeriveClaimState(in)
	if got != derive.StateCandidate {
		t.Errorf("want CANDIDATE, got %s", got)
	}
}

// ── PropagateStale ────────────────────────────────────────────────────────────

func TestPropagateStale_SingleNode(t *testing.T) {
	t.Parallel()
	states := map[string]derive.ClaimStateV2{
		"root": derive.StateGloballyVerified,
	}
	result := derive.PropagateStale(states, map[string][]string{}, "root")
	if result["root"] != derive.StateStale {
		t.Errorf("root should be STALE, got %s", result["root"])
	}
}

func TestPropagateStale_DownstreamPropagation(t *testing.T) {
	t.Parallel()
	// Graph: changed → mid → leaf
	states := map[string]derive.ClaimStateV2{
		"changed":   derive.StateGloballyVerified,
		"mid":       derive.StateGloballyVerified,
		"leaf":      derive.StateGloballyVerified,
		"unrelated": derive.StateLocallyVerified,
	}
	reverseEdges := map[string][]string{
		"changed": {"mid"},
		"mid":     {"leaf"},
	}
	result := derive.PropagateStale(states, reverseEdges, "changed")

	for _, id := range []string{"changed", "mid", "leaf"} {
		if result[id] != derive.StateStale {
			t.Errorf("%s should be STALE, got %s", id, result[id])
		}
	}
	if result["unrelated"] == derive.StateStale {
		t.Error("unrelated node must not become STALE")
	}
}

func TestPropagateStale_DoesNotMutateOriginal(t *testing.T) {
	t.Parallel()
	states := map[string]derive.ClaimStateV2{
		"a": derive.StateGloballyVerified,
		"b": derive.StateLocallyVerified,
	}
	_ = derive.PropagateStale(states, map[string][]string{"a": {"b"}}, "a")
	if states["a"] != derive.StateGloballyVerified {
		t.Error("PropagateStale must not mutate the original states map")
	}
}

func TestPropagateStale_CycleGuard(t *testing.T) {
	t.Parallel()
	// Cycle: a → b → a; propagation must terminate.
	states := map[string]derive.ClaimStateV2{
		"a": derive.StateGloballyVerified,
		"b": derive.StateGloballyVerified,
	}
	reverseEdges := map[string][]string{
		"a": {"b"},
		"b": {"a"},
	}
	result := derive.PropagateStale(states, reverseEdges, "a")
	if result["a"] != derive.StateStale || result["b"] != derive.StateStale {
		t.Error("both nodes should be STALE")
	}
}

// ── stateOrdinal coverage ─────────────────────────────────────────────────────

// Exercise every ClaimStateV2 through stateAtLeast (which calls stateOrdinal)
// by constructing DeriveInput scenarios that require each state to be evaluated.
func TestStateOrdinal_AllStates(t *testing.T) {
	t.Parallel()
	// We drive stateOrdinal coverage by using states as RequiredDepStates values
	// inside DeriveClaimState, which calls stateAtLeast internally.
	allStates := []derive.ClaimStateV2{
		derive.StateOpen,
		derive.StateCandidate,
		derive.StateLocallyVerified,
		derive.StateGloballyVerified,
		derive.StateReproducible,
		derive.StateReleased,
		derive.StateStale,
		derive.StateBlocked,
	}
	for _, s := range allStates {
		s := s
		t.Run(string(s), func(t *testing.T) {
			t.Parallel()
			// Put the state as both actual and required dep state → should satisfy.
			in := baseVerifiedInput()
			in.DepStates = map[string]derive.ClaimStateV2{"dep1": s}
			in.RequiredDepStates = map[string]derive.ClaimStateV2{"dep1": s}
			// We just call DeriveClaimState to exercise stateOrdinal; we don't
			// assert a specific result here since BLOCKED/STALE deps have special rules.
			_ = derive.DeriveClaimState(in)
		})
	}
}

// Unknown state string should fall through to default ordinal (-2).
func TestStateOrdinal_Unknown(t *testing.T) {
	t.Parallel()
	// An unknown state as a dep value should be treated as lowest (not satisfying any requirement).
	in := baseVerifiedInput()
	in.DepStates = map[string]derive.ClaimStateV2{"dep1": derive.ClaimStateV2("unknown-state")}
	in.RequiredDepStates = map[string]derive.ClaimStateV2{"dep1": derive.StateLocallyVerified}
	got := derive.DeriveClaimState(in)
	// unknown dep state cannot satisfy LV requirement → LOCALLY_VERIFIED (not GV)
	if got != derive.StateLocallyVerified {
		t.Errorf("unknown dep state should not satisfy any requirement, want LOCALLY_VERIFIED, got %s", got)
	}
}
