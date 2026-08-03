// Package release implements the release gate for the ProofGraph Engine.
package release

import (
	"fmt"
	"strings"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
)

// ConditionID identifies a release condition.
type ConditionID string

const (
	CondGlobalStatusAccepted     ConditionID = "C01-global-status-accepted"
	CondAssumptionFootprintEmpty ConditionID = "C02-assumption-footprint-empty"
	CondAllAssurancesAllowed     ConditionID = "C03-assurances-allowed"
	CondReplayConsistency        ConditionID = "C04-replay-consistency"
	CondAttestationSignatures    ConditionID = "C05-attestation-signatures"
)

// ConditionResult records whether one release condition passed.
type ConditionResult struct {
	ID      ConditionID `json:"id"`
	Passed  bool        `json:"passed"`
	Blocker string      `json:"blocker,omitempty"`
}

// EvaluateConditions checks the four universal conditions plus any
// domain-specific metadata key conditions declared in the policy.
// Universal conditions: C01 (all claims accepted), C02 (no assumption assurance),
// C03 (assurances allowed), C04 (replay consistency).
// Conditional: C05 (attestation signatures) — only when policy.RequireSignedAttestations.
// Domain conditions: one condition per key in pol.RequiredMetadataKeys.
func EvaluateConditions(
	graph *dag.DAG,
	attestations map[string]*ir.Attestation,
	pol policy.ReleasePolicy,
) []ConditionResult {
	results := make([]ConditionResult, 0, 5+len(pol.RequiredMetadataKeys))
	results = append(results, checkC01GlobalStatus(graph, attestations))
	results = append(results, checkC02AssumptionFootprint(attestations))
	results = append(results, checkC03AssurancesAllowed(attestations, pol))
	results = append(results, checkC04ReplayConsistency(graph, attestations))
	if pol.RequireSignedAttestations {
		results = append(results, checkC05AttestationSignatures(attestations))
	}
	for _, key := range pol.RequiredMetadataKeys {
		results = append(results, checkMetadataKey(attestations, key))
	}
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

// checkC04ReplayConsistency checks that every attestation has non-empty
// SelfDigest and StartFreshness/EndFreshness (proxy for recorded replay).
func checkC04ReplayConsistency(graph *dag.DAG, attestations map[string]*ir.Attestation) ConditionResult {
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
			Blocker: "C04: replay consistency missing for: " + strings.Join(missing, ", "),
		}
	}
	return ConditionResult{ID: CondReplayConsistency, Passed: true}
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

// checkMetadataKey is the generic domain condition: passes if any attestation
// carries a non-empty value for key. Used for all policy.RequiredMetadataKeys entries.
func checkMetadataKey(attestations map[string]*ir.Attestation, key string) ConditionResult {
	id := ConditionID("meta:" + key)
	if !hasMetaKey(attestations, key) {
		return ConditionResult{
			ID:      id,
			Passed:  false,
			Blocker: fmt.Sprintf("meta:%s: no checker attestation for key %q — not yet verified", key, key),
		}
	}
	return ConditionResult{ID: id, Passed: true}
}

// checkC05AttestationSignatures verifies that every attestation carries a signature.
// Unsigned attestations fail this condition when policy.RequireSignedAttestations is true.
func checkC05AttestationSignatures(attestations map[string]*ir.Attestation) ConditionResult {
	var unsigned []string
	for id, att := range attestations {
		if att.Signature == nil || att.Signature.Value == "" {
			unsigned = append(unsigned, id)
		}
	}
	if len(unsigned) > 0 {
		return ConditionResult{
			ID:      CondAttestationSignatures,
			Passed:  false,
			Blocker: "C05: unsigned attestations: " + strings.Join(unsigned, ", "),
		}
	}
	return ConditionResult{ID: CondAttestationSignatures, Passed: true}
}
