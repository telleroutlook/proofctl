// Package derive implements the v2 claim state machine.
//
// States are DERIVED from the current identity closure and Contract — they
// are never read from writable attestation fields. proofverify calls
// DeriveClaimState for every node in the DAG to produce the authoritative
// state projection.
//
// State transition rules (INV-05, INV-06, INV-07, INV-08, INV-09):
//
//	OPEN             → evidence not yet fully present
//	CANDIDATE        → evidence exists but no qualifying checker result
//	LOCALLY_VERIFIED → all Contract obligations pass with exact-set match
//	GLOBALLY_VERIFIED → all deps at required state; assurance/policy closed
//	REPRODUCIBLE     → Contract-required replay passed
//	RELEASED         → root claim reached GLOBALLY_VERIFIED and manifest signed
//	STALE            → attestation.claim_identity_digest ≠ current identity
//	BLOCKED          → any required obligation verdict == fail
package derive

// ClaimStateV2 is the derived state of a claim under the v2 kernel.
// Values are lowercase strings matching the canonical wire representation.
type ClaimStateV2 string

const (
	StateOpen             ClaimStateV2 = "OPEN"
	StateCandidate        ClaimStateV2 = "CANDIDATE"
	StateLocallyVerified  ClaimStateV2 = "LOCALLY_VERIFIED"
	StateGloballyVerified ClaimStateV2 = "GLOBALLY_VERIFIED"
	StateReproducible     ClaimStateV2 = "REPRODUCIBLE"
	StateReleased         ClaimStateV2 = "RELEASED"
	StateStale            ClaimStateV2 = "STALE"
	StateBlocked          ClaimStateV2 = "BLOCKED"
)

// EvidencePresence describes whether an evidence set is fully available in CAS.
type EvidencePresence int

const (
	EvidenceAbsent  EvidencePresence = iota // no required evidence in CAS
	EvidencePartial                         // some but not all evidence present
	EvidencePresent                         // all required evidence present
)

// ObligationSetResult describes the result of exact-set obligation validation.
type ObligationSetResult int

const (
	ObligationSetAbsent   ObligationSetResult = iota // no checker result
	ObligationSetMismatch                            // wrong set of IDs (INV-06 violation)
	ObligationSetFail                                // correct set but ≥1 verdict == fail
	ObligationSetPass                                // exact set, all verdicts pass
)

// DeriveInput holds all data needed to derive one claim's state.
// All fields are computed from immutable inputs; nothing is read from
// a writable status/outcome field.
type DeriveInput struct {
	// ClaimID is the identifier of the claim being derived.
	ClaimID string

	// CurrentIdentity is the identity digest computed from the current inputs
	// (via identity.Compute). Compared against AttestationIdentity.
	CurrentIdentity string

	// AttestationIdentity is the identity digest recorded in the stored
	// attestation. Empty if no attestation exists.
	AttestationIdentity string

	// Evidence describes whether the claim's required evidence is in CAS.
	Evidence EvidencePresence

	// ObligationSet describes the checker's obligation results, if any.
	ObligationSet ObligationSetResult

	// DepStates maps each dependency claim ID to its derived state.
	// Required dependency states come from the Contract.
	DepStates map[string]ClaimStateV2

	// RequiredDepStates maps each dep claim ID to the minimum state
	// required by this claim's Contract before proceeding (INV-08).
	RequiredDepStates map[string]ClaimStateV2

	// HasReplay indicates whether a qualifying replay result exists.
	HasReplay bool

	// IsReleaseRoot is true when this claim is the release root and a
	// signed manifest exists.
	IsReleaseRoot     bool
	HasSignedManifest bool
}

// DeriveClaimState computes the canonical state for a single claim.
//
// Rules are applied in strict priority order:
//  1. If AttestationIdentity is set and differs from CurrentIdentity → STALE (INV-09)
//  2. If any dep is BLOCKED → BLOCKED (INV-08: block propagates)
//  3. If ObligationSet has ≥1 fail or set mismatch → BLOCKED (INV-07/INV-06)
//  4. If ObligationSet is absent and Evidence is absent/partial → OPEN
//  5. If ObligationSet is absent but Evidence is present → CANDIDATE
//  6. If ObligationSet passes exactly and all deps at required state → GLOBALLY_VERIFIED
//  7. If ObligationSet passes exactly but some dep below required state → LOCALLY_VERIFIED
//     (INV-08: dep not at required state prevents upgrade, but does not propagate BLOCKED)
//  8. If GLOBALLY_VERIFIED and HasReplay → REPRODUCIBLE
//  9. If (GLOBALLY_VERIFIED or REPRODUCIBLE) and IsReleaseRoot and HasSignedManifest → RELEASED
func DeriveClaimState(in DeriveInput) ClaimStateV2 {
	// Rule 1: staleness check (INV-09)
	if in.AttestationIdentity != "" && in.AttestationIdentity != in.CurrentIdentity {
		return StateStale
	}

	// Rule 2: propagate BLOCKED from deps (INV-08)
	for _, depState := range in.DepStates {
		if depState == StateBlocked {
			return StateBlocked
		}
	}

	// Rule 3: failing obligations → BLOCKED (INV-06, INV-07)
	if in.ObligationSet == ObligationSetFail || in.ObligationSet == ObligationSetMismatch {
		return StateBlocked
	}

	// Rules 4-5: no checker result yet
	if in.ObligationSet == ObligationSetAbsent {
		if in.Evidence == EvidenceAbsent || in.Evidence == EvidencePartial {
			return StateOpen
		}
		return StateCandidate
	}

	// Rule 6/7: obligations pass exactly — determine if deps allow GV upgrade.
	if in.ObligationSet != ObligationSetPass {
		return StateBlocked
	}

	// Check whether all required deps are at required state (INV-08).
	depsGV := true
	for depID, required := range in.RequiredDepStates {
		actual, ok := in.DepStates[depID]
		if !ok || !stateAtLeast(actual, required) {
			depsGV = false
			break
		}
	}
	if !depsGV {
		// Obligations pass locally but deps not ready — stay LOCALLY_VERIFIED (INV-08).
		return StateLocallyVerified
	}

	// Rule 8: deps at required state → GLOBALLY_VERIFIED or higher.
	// Rule 9/10: replay and release.
	if in.HasReplay {
		if in.IsReleaseRoot && in.HasSignedManifest {
			return StateReleased
		}
		return StateReproducible
	}
	if in.IsReleaseRoot && in.HasSignedManifest {
		return StateReleased
	}
	return StateGloballyVerified
}

// stateAtLeast returns true if actual is at least as advanced as required
// in the canonical state progression.
func stateAtLeast(actual, required ClaimStateV2) bool {
	return stateOrdinal(actual) >= stateOrdinal(required)
}

func stateOrdinal(s ClaimStateV2) int {
	switch s {
	case StateBlocked:
		return -1
	case StateStale:
		return -1
	case StateOpen:
		return 0
	case StateCandidate:
		return 1
	case StateLocallyVerified:
		return 2
	case StateGloballyVerified:
		return 3
	case StateReproducible:
		return 4
	case StateReleased:
		return 5
	default:
		return -2
	}
}

// PropagateStale marks changedClaimID and all its downstream dependents as STALE.
// reverseEdges maps each claim ID to the set of claim IDs that directly depend on it.
// Returns the updated states map (original is not mutated).
func PropagateStale(
	states map[string]ClaimStateV2,
	reverseEdges map[string][]string,
	changedClaimID string,
) map[string]ClaimStateV2 {
	result := make(map[string]ClaimStateV2, len(states))
	for k, v := range states {
		result[k] = v
	}

	visited := make(map[string]bool)
	queue := []string{changedClaimID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if visited[cur] {
			continue
		}
		visited[cur] = true
		result[cur] = StateStale
		queue = append(queue, reverseEdges[cur]...)
	}
	return result
}
