// Package release implements the release gate for the ProofGraph Engine.
package release

import (
	"fmt"
	"strings"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
)

// ConditionID identifies one of the 13 Weil release conditions.
type ConditionID string

const (
	CondGlobalStatusAccepted    ConditionID = "C01-global-status-accepted"
	CondAssumptionFootprintEmpty ConditionID = "C02-assumption-footprint-empty"
	CondAllAssurancesAllowed    ConditionID = "C03-assurances-allowed"
	CondCAPFormatV2Frozen       ConditionID = "C04-cap-format-v2-frozen"
	CondDigestsFresh            ConditionID = "C05-digests-fresh"
	CondPathKeysMatch           ConditionID = "C06-path-keys-match"
	CondIntervalsIntersect      ConditionID = "C07-intervals-intersect"
	CondMatrixReconstructed     ConditionID = "C08-matrix-reconstructed"
	CondLDLTPasses              ConditionID = "C09-ldlt-passes"
	CondOddSectorPasses         ConditionID = "C10-odd-sector-passes"
	CondEvenSectorPasses        ConditionID = "C11-even-sector-passes"
	CondPivotRadiusRatio        ConditionID = "C12-pivot-radius-ratio"
	CondReplayConsistency       ConditionID = "C13-replay-consistency"
)

// ConditionResult records whether one release condition passed.
type ConditionResult struct {
	ID      ConditionID `json:"id"`
	Passed  bool        `json:"passed"`
	Blocker string      `json:"blocker,omitempty"`
}

// EvaluateConditions checks all 13 release conditions against the proof graph and attestations.
// Returns one result per condition, in order C01-C13.
func EvaluateConditions(
	graph *dag.DAG,
	attestations map[string]*ir.Attestation,
	pol policy.ReleasePolicy,
) []ConditionResult {
	results := make([]ConditionResult, 0, 13)
	results = append(results, checkC01GlobalStatus(graph, attestations))
	results = append(results, checkC02AssumptionFootprint(attestations))
	results = append(results, checkC03AssurancesAllowed(attestations, pol))
	results = append(results, checkC04CAPFormat(attestations))
	results = append(results, checkC05DigestsFresh(attestations))
	results = append(results, checkC06PathKeys(attestations))
	results = append(results, checkC07IntervalsIntersect(attestations))
	results = append(results, checkC08MatrixReconstructed(attestations))
	results = append(results, checkC09LDLT(attestations))
	results = append(results, checkC10OddSector(attestations))
	results = append(results, checkC11EvenSector(attestations))
	results = append(results, checkC12PivotRatio(attestations))
	results = append(results, checkC13ReplayConsistency(graph, attestations))
	return results
}

// AllPassed returns true only if every condition passed.
func AllPassed(results []ConditionResult) bool {
	for _, r := range results {
		if !r.Passed {
			return false
		}
	}
	return true
}

// Blockers returns the blocker strings for all failed conditions.
func Blockers(results []ConditionResult) []string {
	var out []string
	for _, r := range results {
		if !r.Passed {
			out = append(out, fmt.Sprintf("[%s] %s", r.ID, r.Blocker))
		}
	}
	return out
}

// checkC01GlobalStatus checks that every claim in the graph has an accepted attestation.
func checkC01GlobalStatus(graph *dag.DAG, attestations map[string]*ir.Attestation) ConditionResult {
	var failed []string
	for _, c := range graph.Claims() {
		att, ok := attestations[c.ID]
		if !ok {
			failed = append(failed, c.ID)
			continue
		}
		if att.Outcome != string(ir.StatusAccepted) {
			failed = append(failed, fmt.Sprintf("%s(outcome=%s)", c.ID, att.Outcome))
		}
	}
	if len(failed) > 0 {
		return ConditionResult{
			ID:      CondGlobalStatusAccepted,
			Passed:  false,
			Blocker: "C01: claims not accepted: " + strings.Join(failed, ", "),
		}
	}
	return ConditionResult{ID: CondGlobalStatusAccepted, Passed: true}
}

// checkC02AssumptionFootprint checks that no attestation has assurance "assumption".
func checkC02AssumptionFootprint(attestations map[string]*ir.Attestation) ConditionResult {
	var found []string
	for id, att := range attestations {
		if att.Assurance == ir.AssuranceAssumption {
			found = append(found, id)
		}
	}
	if len(found) > 0 {
		return ConditionResult{
			ID:      CondAssumptionFootprintEmpty,
			Passed:  false,
			Blocker: "C02: assumption assurance found in claims: " + strings.Join(found, ", "),
		}
	}
	return ConditionResult{ID: CondAssumptionFootprintEmpty, Passed: true}
}

// checkC03AssurancesAllowed checks that every attestation's assurance is allowed and not forbidden.
func checkC03AssurancesAllowed(attestations map[string]*ir.Attestation, pol policy.ReleasePolicy) ConditionResult {
	forbidden := make(map[string]bool, len(pol.ForbiddenAssurances))
	for _, a := range pol.ForbiddenAssurances {
		forbidden[a] = true
	}
	allowed := make(map[string]bool, len(pol.AllowedAssurances))
	for _, a := range pol.AllowedAssurances {
		allowed[a] = true
	}

	var violations []string
	for id, att := range attestations {
		assurance := string(att.Assurance)
		if forbidden[assurance] {
			violations = append(violations, fmt.Sprintf("%s uses forbidden assurance %q", id, assurance))
			continue
		}
		if len(pol.AllowedAssurances) > 0 && !allowed[assurance] {
			violations = append(violations, fmt.Sprintf("%s uses assurance %q not in allowed list", id, assurance))
		}
	}
	if len(violations) > 0 {
		return ConditionResult{
			ID:      CondAllAssurancesAllowed,
			Passed:  false,
			Blocker: "C03: assurance violations: " + strings.Join(violations, "; "),
		}
	}
	return ConditionResult{ID: CondAllAssurancesAllowed, Passed: true}
}

// shadowBlocker returns a standard shadow-mode blocker message for C04-C12.
func shadowBlocker(cond ConditionID, metaKey string) ConditionResult {
	return ConditionResult{
		ID:      cond,
		Passed:  false,
		Blocker: fmt.Sprintf("%s: no checker attestation for key %q — shadow mode, not yet verified", cond, metaKey),
	}
}

// hasMetaKey returns true if any attestation contains a non-empty value for the given metadata key.
func hasMetaKey(attestations map[string]*ir.Attestation, key string) bool {
	for _, att := range attestations {
		if att.Metadata != nil {
			if v, ok := att.Metadata[key]; ok && v != "" {
				return true
			}
		}
	}
	return false
}

// checkC04CAPFormat checks that at least one attestation reports cap_format_version.
func checkC04CAPFormat(attestations map[string]*ir.Attestation) ConditionResult {
	const key = "cap_format_version"
	if !hasMetaKey(attestations, key) {
		return shadowBlocker(CondCAPFormatV2Frozen, key)
	}
	return ConditionResult{ID: CondCAPFormatV2Frozen, Passed: true}
}

// checkC05DigestsFresh checks that at least one attestation reports digests_fresh.
func checkC05DigestsFresh(attestations map[string]*ir.Attestation) ConditionResult {
	const key = "digests_fresh"
	if !hasMetaKey(attestations, key) {
		return shadowBlocker(CondDigestsFresh, key)
	}
	return ConditionResult{ID: CondDigestsFresh, Passed: true}
}

// checkC06PathKeys checks that at least one attestation reports path_keys_match.
func checkC06PathKeys(attestations map[string]*ir.Attestation) ConditionResult {
	const key = "path_keys_match"
	if !hasMetaKey(attestations, key) {
		return shadowBlocker(CondPathKeysMatch, key)
	}
	return ConditionResult{ID: CondPathKeysMatch, Passed: true}
}

// checkC07IntervalsIntersect checks that at least one attestation reports intervals_intersect.
func checkC07IntervalsIntersect(attestations map[string]*ir.Attestation) ConditionResult {
	const key = "intervals_intersect"
	if !hasMetaKey(attestations, key) {
		return shadowBlocker(CondIntervalsIntersect, key)
	}
	return ConditionResult{ID: CondIntervalsIntersect, Passed: true}
}

// checkC08MatrixReconstructed checks that at least one attestation reports matrix_reconstructed.
func checkC08MatrixReconstructed(attestations map[string]*ir.Attestation) ConditionResult {
	const key = "matrix_reconstructed"
	if !hasMetaKey(attestations, key) {
		return shadowBlocker(CondMatrixReconstructed, key)
	}
	return ConditionResult{ID: CondMatrixReconstructed, Passed: true}
}

// checkC09LDLT checks that at least one attestation reports ldlt_passes.
func checkC09LDLT(attestations map[string]*ir.Attestation) ConditionResult {
	const key = "ldlt_passes"
	if !hasMetaKey(attestations, key) {
		return shadowBlocker(CondLDLTPasses, key)
	}
	return ConditionResult{ID: CondLDLTPasses, Passed: true}
}

// checkC10OddSector checks that at least one attestation reports odd_sector_passes.
func checkC10OddSector(attestations map[string]*ir.Attestation) ConditionResult {
	const key = "odd_sector_passes"
	if !hasMetaKey(attestations, key) {
		return shadowBlocker(CondOddSectorPasses, key)
	}
	return ConditionResult{ID: CondOddSectorPasses, Passed: true}
}

// checkC11EvenSector checks that at least one attestation reports even_sector_passes.
func checkC11EvenSector(attestations map[string]*ir.Attestation) ConditionResult {
	const key = "even_sector_passes"
	if !hasMetaKey(attestations, key) {
		return shadowBlocker(CondEvenSectorPasses, key)
	}
	return ConditionResult{ID: CondEvenSectorPasses, Passed: true}
}

// checkC12PivotRatio checks that at least one attestation reports pivot_radius_ratio.
func checkC12PivotRatio(attestations map[string]*ir.Attestation) ConditionResult {
	const key = "pivot_radius_ratio"
	if !hasMetaKey(attestations, key) {
		return shadowBlocker(CondPivotRadiusRatio, key)
	}
	return ConditionResult{ID: CondPivotRadiusRatio, Passed: true}
}

// checkC13ReplayConsistency checks that every attestation has non-empty
// SelfDigest and StartFreshness/EndFreshness (proxy for recorded replay).
func checkC13ReplayConsistency(graph *dag.DAG, attestations map[string]*ir.Attestation) ConditionResult {
	var missing []string
	for _, c := range graph.Claims() {
		att, ok := attestations[c.ID]
		if !ok {
			missing = append(missing, fmt.Sprintf("%s(no attestation)", c.ID))
			continue
		}
		if att.SelfDigest == "" || att.StartFreshness == "" || att.EndFreshness == "" {
			missing = append(missing, fmt.Sprintf("%s(missing freshness/digest)", c.ID))
		}
	}
	if len(missing) > 0 {
		return ConditionResult{
			ID:      CondReplayConsistency,
			Passed:  false,
			Blocker: "C13: replay consistency missing for: " + strings.Join(missing, ", "),
		}
	}
	return ConditionResult{ID: CondReplayConsistency, Passed: true}
}
