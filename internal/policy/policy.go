// Package policy implements release policy evaluation for the ProofGraph Engine.
package policy

import (
	"fmt"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// ReleasePolicy defines the assurance and claim requirements for a release gate.
type ReleasePolicy struct {
	Version             string   `json:"version"`
	Target              string   `json:"target"`
	AllowedAssurances   []string `json:"allowed_assurances"`
	ForbiddenAssurances []string `json:"forbidden_assurances"`
	RequiredClaims      []string `json:"required_claims"`
	// RequiredMetadataKeys lists attestation metadata keys that must be present
	// and non-empty in at least one attestation for a release to pass.
	// This replaces the former hardcoded Weil-specific C04-C12 conditions.
	RequiredMetadataKeys []string `json:"required_metadata_keys,omitempty"`
	// RequireSignedAttestations activates C05: all attestations must carry a
	// valid Ed25519 signature. Unsigned attestations are rejected at release.
	RequireSignedAttestations bool `json:"require_signed_attestations,omitempty"`
	// AllowedMetadataValues constrains the permitted values for specific attestation
	// metadata keys. Key: metadata key name. Value: list of allowed values. Any
	// attestation whose metadata key holds a value not in the list blocks release.
	// Useful to ban specific computation paths (e.g. forbid gl_self_convergence as
	// a remainder type).
	AllowedMetadataValues map[string][]string `json:"allowed_metadata_values,omitempty"`
	// ConditionalMetadataKeys declares keys that must be present when a trigger key
	// is found in any attestation. Key: trigger metadata key. Value: required metadata
	// key. If any attestation contains the trigger key, at least one attestation must
	// also contain the required key. Used to enforce, e.g., drpp_bound_proof whenever
	// kernel_branch witnesses are present.
	ConditionalMetadataKeys map[string]string `json:"conditional_metadata_keys,omitempty"`
	// RequiredReplayMode, if set, requires that all attestations carry the specified
	// replay_mode value. Accepted values: "from_scratch", "self_consistency".
	RequiredReplayMode string `json:"required_replay_mode,omitempty"`
	// ForbiddenRuntimes lists runtime Kind values that must not appear in any
	// attestation contributing to release (INV-10). Typically ["native", "native-dev"].
	// Use this to prevent development-only checker results from reaching a formal release.
	ForbiddenRuntimes []string `json:"forbidden_runtimes,omitempty"`
	// ForbidCopyOnlyGenerators activates C10: any attestation that claims
	// substantive recomputation (replay_mode=="from_scratch") but whose
	// generator_cmds metadata is a pure file-copy (shutil.copy, cp, ...) is
	// rejected. This closes the shell-game bypass where a certificate is copied
	// into place and self-attests as if recomputed from scratch (pilot: weil
	// FP-0.35 certificate copied via shutil.copy but marked from_scratch).
	ForbidCopyOnlyGenerators bool `json:"forbid_copy_only_generators,omitempty"`
	// RequireCheckerMutationCoverage activates C11: every attestation that claims
	// substantive recomputation (replay_mode==from_scratch or assurance
	// reproducible-computation/exact-replay) must carry evidence that its checker
	// was run against a mutation catalog and rejected ALL mutants
	// (metadata mutation_kill_rate=="100%" and a non-empty mutation_catalog_digest).
	// This closes the "honest but incomplete checker" gap: a checker that computes
	// for real yet omits a term (e.g. a second-moment) can still emit a false pass;
	// mutation coverage proves the checker is actually sensitive to every asserted
	// term. Complements C10 (which only blocks copy-only generators). Pilot: the
	// Weil FP-0.35 checker omitted S^(2)/S_VV terms and passed regardless.
	RequireCheckerMutationCoverage bool `json:"require_checker_mutation_coverage,omitempty"`
}

// Evaluate checks that all required claims are accepted and exist in the graph.
// Assurance constraints (allowed/forbidden lists) are enforced exclusively by
// conditions.go C03 to avoid duplicate, divergent checks.
//
// It returns (true, nil) on pass and (false, blockers) on failure, where blockers is a
// list of human-readable failure reasons.
func Evaluate(graph *dag.DAG, attestations map[string]*ir.Attestation, policy ReleasePolicy) (bool, []string) {
	var blockers []string

	// Check required claims are all accepted.
	for _, claimID := range policy.RequiredClaims {
		att, ok := attestations[claimID]
		if !ok {
			blockers = append(blockers, fmt.Sprintf("required claim %q has no attestation", claimID))
			continue
		}
		if att.Outcome != string(ir.StatusAccepted) {
			blockers = append(blockers, fmt.Sprintf("required claim %q outcome is %q, want %q",
				claimID, att.Outcome, ir.StatusAccepted))
		}
	}

	// Verify all claims in the required set actually exist in the graph.
	for _, claimID := range policy.RequiredClaims {
		if graph.Claim(claimID) == nil {
			blockers = append(blockers, fmt.Sprintf("required claim %q does not exist in graph", claimID))
		}
	}

	return len(blockers) == 0, blockers
}
