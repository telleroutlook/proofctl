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
//  2. If any dep is BLOCKED → BLOCKED (INV-08)
//  3. If any required dep has not reached RequiredDepStates → BLOCKED (INV-08)
//  4. If ObligationSet has ≥1 fail → BLOCKED (INV-07)
//  5. If ObligationSet is absent and Evidence is absent → OPEN
//  6. If ObligationSet is absent but Evidence exists → CANDIDATE
//  7. If ObligationSet passes exactly → LOCALLY_VERIFIED
//  8. If all deps at required state and policy closed → GLOBALLY_VERIFIED
//  9. If HasReplay → REPRODUCIBLE
//
// 10. If IsReleaseRoot and HasSignedManifest → RELEASED
func DeriveClaimState(in DeriveInput) ClaimStateV2 {
	// Rule 1: staleness check (INV-09)
	if in.AttestationIdentity != "" && in.AttestationIdentity != in.CurrentIdentity {
		return StateStale
	}

	// Rule 2+3: dependency blocking (INV-08)
	for depID, depState := range in.DepStates {
		if depState == StateBlocked {
			_ = depID
			return StateBlocked
		}
		if required, ok := in.RequiredDepStates[depID]; ok {
			if !stateAtLeast(depState, required) {
				return StateBlocked
			}
		}
	}

	// Rule 4: any failing obligation (INV-07)
	if in.ObligationSet == ObligationSetFail || in.ObligationSet == ObligationSetMismatch {
		return StateBlocked
	}

	// Rules 5-6: no checker result yet
	if in.ObligationSet == ObligationSetAbsent {
		if in.Evidence == EvidenceAbsent || in.Evidence == EvidencePartial {
			return StateOpen
		}
		return StateCandidate
	}

	// Rule 7: obligations pass exactly
	if in.ObligationSet != ObligationSetPass {
		return StateBlocked
	}

	// Check deps for GLOBALLY_VERIFIED
	depsGV := true
	for depID, required := range in.RequiredDepStates {
		if actual, ok := in.DepStates[depID]; !ok || !stateAtLeast(actual, required) {
			depsGV = false
			break
		}
	}
	if !depsGV {
		return StateLocallyVerified
	}

	// Rule 9: replay
	if in.HasReplay {
		// Rule 10: signed release
		if in.IsReleaseRoot && in.HasSignedManifest {
			return StateReleased
		}
		return StateReproducible
	}

	// Rule 8: globally verified
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
