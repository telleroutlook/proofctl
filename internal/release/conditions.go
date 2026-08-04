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
	CondMetadataValues           ConditionID = "C06-metadata-values"
	CondConditionalMetadata      ConditionID = "C07-conditional-metadata"
	CondReplayMode               ConditionID = "C08-replay-mode"
	CondNoNativeRuntime          ConditionID = "C09-no-native-runtime"
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
// Conditional: C06 (metadata values) — only when policy.AllowedMetadataValues is set.
// Conditional: C07 (conditional metadata keys) — only when policy.ConditionalMetadataKeys is set.
// Conditional: C08 (replay mode) — only when policy.RequiredReplayMode is set.
// Conditional: C09 (no native runtime) — only when policy.ForbiddenRuntimes is set (INV-10).
// Domain conditions: one condition per key in pol.RequiredMetadataKeys.
func EvaluateConditions(
	graph *dag.DAG,
	attestations map[string]*ir.Attestation,
	pol policy.ReleasePolicy,
) []ConditionResult {
	results := make([]ConditionResult, 0, 9+len(pol.RequiredMetadataKeys))
	results = append(results, checkC01GlobalStatus(graph, attestations))
	results = append(results, checkC02AssumptionFootprint(attestations))
	results = append(results, checkC03AssurancesAllowed(attestations, pol))
	results = append(results, checkC04ReplayConsistency(graph, attestations))
	if pol.RequireSignedAttestations {
		results = append(results, checkC05AttestationSignatures(attestations))
	}
	if len(pol.AllowedMetadataValues) > 0 {
		results = append(results, checkC06MetadataValues(attestations, pol.AllowedMetadataValues))
	}
	if len(pol.ConditionalMetadataKeys) > 0 {
		results = append(results, checkC07ConditionalMetadata(attestations, pol.ConditionalMetadataKeys))
	}
	if pol.RequiredReplayMode != "" {
		results = append(results, checkC08ReplayMode(attestations, pol.RequiredReplayMode))
	}
	if len(pol.ForbiddenRuntimes) > 0 {
		results = append(results, checkC09NoNativeRuntime(attestations, pol.ForbiddenRuntimes))
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

// checkC04ReplayConsistency checks that every claim with a checker_policy has
// non-empty SelfDigest and StartFreshness/EndFreshness (proxy for recorded
// replay or check). Claims without a checker_policy (manual attest) are exempt
// because they have no generator and the freshness is now auto-populated by
// proofctl attest.
func checkC04ReplayConsistency(graph *dag.DAG, attestations map[string]*ir.Attestation) ConditionResult {
	var missing []string
	for _, c := range graph.Claims() {
		// Claims without a checker_policy are manually attested; skip freshness check.
		if c.CheckerPolicy == "" {
			continue
		}
		att, ok := attestations[c.ID]
		if !ok {
			missing = append(missing, fmt.Sprintf("%s(no attestation)", c.ID))
			continue
		}
		if att.SelfDigest == "" || att.StartFreshness == "" || att.EndFreshness == "" {
			var absent []string
			if att.SelfDigest == "" {
				absent = append(absent, "self_digest")
			}
			if att.StartFreshness == "" {
				absent = append(absent, "start_freshness")
			}
			if att.EndFreshness == "" {
				absent = append(absent, "end_freshness")
			}
			missing = append(missing, fmt.Sprintf("%s(missing: %s)", c.ID, strings.Join(absent, ", ")))
		}
	}
	if len(missing) > 0 {
		return ConditionResult{
			ID:      CondReplayConsistency,
			Passed:  false,
			Blocker: "C04: replay consistency missing for: " + strings.Join(missing, ", ") + " — run 'proofctl check' or 'proofctl replay' to populate freshness fields",
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

// checkC06MetadataValues enforces allowed_metadata_values: for each constrained key,
// every attestation that carries that key must have a value in the allowed set.
// Attestations that do not have the key at all are exempt (use required_metadata_keys
// to require presence separately).
func checkC06MetadataValues(attestations map[string]*ir.Attestation, allowed map[string][]string) ConditionResult {
	allowedSet := make(map[string]map[string]bool, len(allowed))
	for key, vals := range allowed {
		s := make(map[string]bool, len(vals))
		for _, v := range vals {
			s[v] = true
		}
		allowedSet[key] = s
	}

	var violations []string
	for claimID, att := range attestations {
		for key, permittedVals := range allowedSet {
			val, ok := att.Metadata[key]
			if !ok {
				continue // key absent — not a violation; use required_metadata_keys for presence
			}
			if !permittedVals[val] {
				var allowed []string
				for v := range permittedVals {
					allowed = append(allowed, v)
				}
				violations = append(violations,
					fmt.Sprintf("%s: metadata key %q has value %q, allowed: %s",
						claimID, key, val, strings.Join(allowed, ", ")))
			}
		}
	}
	if len(violations) > 0 {
		return ConditionResult{
			ID:      CondMetadataValues,
			Passed:  false,
			Blocker: "C06: metadata value violations: " + strings.Join(violations, "; "),
		}
	}
	return ConditionResult{ID: CondMetadataValues, Passed: true}
}

// checkC07ConditionalMetadata enforces conditional_metadata_keys: if any attestation
// contains the trigger key, at least one attestation must also contain the required key.
func checkC07ConditionalMetadata(attestations map[string]*ir.Attestation, conditionals map[string]string) ConditionResult {
	var violations []string
	for triggerKey, requiredKey := range conditionals {
		triggered := false
		for _, att := range attestations {
			if _, ok := att.Metadata[triggerKey]; ok {
				triggered = true
				break
			}
		}
		if !triggered {
			continue
		}
		// Trigger found — check that at least one attestation has the required key.
		satisfied := false
		for _, att := range attestations {
			if v, ok := att.Metadata[requiredKey]; ok && v != "" {
				satisfied = true
				break
			}
		}
		if !satisfied {
			violations = append(violations,
				fmt.Sprintf("trigger key %q is present but required key %q is absent", triggerKey, requiredKey))
		}
	}
	if len(violations) > 0 {
		return ConditionResult{
			ID:      CondConditionalMetadata,
			Passed:  false,
			Blocker: "C07: conditional metadata violations: " + strings.Join(violations, "; "),
		}
	}
	return ConditionResult{ID: CondConditionalMetadata, Passed: true}
}

// checkC08ReplayMode enforces required_replay_mode: every attestation with a non-empty
// replay_mode must match the required value. Attestations without a replay_mode field
// (written before this field existed) are exempt.
func checkC08ReplayMode(attestations map[string]*ir.Attestation, required string) ConditionResult {
	var violations []string
	for claimID, att := range attestations {
		if att.ReplayMode == "" {
			continue // legacy attestation — exempt
		}
		if att.ReplayMode != required {
			violations = append(violations,
				fmt.Sprintf("%s: replay_mode=%q, want %q", claimID, att.ReplayMode, required))
		}
	}
	if len(violations) > 0 {
		return ConditionResult{
			ID:      CondReplayMode,
			Passed:  false,
			Blocker: "C08: replay mode violations: " + strings.Join(violations, "; "),
		}
	}
	return ConditionResult{ID: CondReplayMode, Passed: true}
}

// checkC09NoNativeRuntime enforces that no attestation in the release closure was
// produced by a native (unisolated) runtime (INV-10).
//
// forbiddenKinds is typically []string{"native", "native-dev"} from policy.ForbiddenRuntimes.
// Any attestation whose Checker.Runtime.Kind appears in forbiddenKinds blocks release.
func checkC09NoNativeRuntime(attestations map[string]*ir.Attestation, forbiddenKinds []string) ConditionResult {
	forbidden := make(map[string]bool, len(forbiddenKinds))
	for _, k := range forbiddenKinds {
		forbidden[k] = true
	}

	var violations []string
	for claimID, att := range attestations {
		kind := att.Checker.Runtime.Kind
		if forbidden[kind] {
			violations = append(violations,
				fmt.Sprintf("%s: runtime.kind=%q is forbidden for release (INV-10)", claimID, kind))
		}
	}
	if len(violations) > 0 {
		return ConditionResult{
			ID:      CondNoNativeRuntime,
			Passed:  false,
			Blocker: "C09: native runtime in release closure: " + strings.Join(violations, "; "),
		}
	}
	return ConditionResult{ID: CondNoNativeRuntime, Passed: true}
}
