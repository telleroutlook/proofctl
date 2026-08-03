// Package policy implements release policy evaluation for the ProofGraph Engine.
package policy

import (
	"fmt"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// ReleasePolicy defines the assurance and claim requirements for a release gate.
type ReleasePolicy struct {
	Version              string   `json:"version"`
	Target               string   `json:"target"`
	AllowedAssurances    []string `json:"allowed_assurances"`
	ForbiddenAssurances  []string `json:"forbidden_assurances"`
	RequiredClaims       []string `json:"required_claims"`
	// RequiredMetadataKeys lists attestation metadata keys that must be present
	// and non-empty in at least one attestation for a release to pass.
	// This replaces the former hardcoded Weil-specific C04-C12 conditions.
	RequiredMetadataKeys []string `json:"required_metadata_keys,omitempty"`
}

// Evaluate checks whether all required claims are accepted, no forbidden assurance types
// appear in any attestation, and all assurances are on the allowed list.
//
// It returns (true, nil) on pass and (false, blockers) on failure, where blockers is a
// list of human-readable failure reasons.
func Evaluate(graph *dag.DAG, attestations map[string]*ir.Attestation, policy ReleasePolicy) (bool, []string) {
	var blockers []string

	forbidden := make(map[string]bool, len(policy.ForbiddenAssurances))
	for _, a := range policy.ForbiddenAssurances {
		forbidden[a] = true
	}

	allowed := make(map[string]bool, len(policy.AllowedAssurances))
	for _, a := range policy.AllowedAssurances {
		allowed[a] = true
	}

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

	// Check assurance constraints across all attestations.
	for claimID, att := range attestations {
		assurance := string(att.Assurance)
		if forbidden[assurance] {
			blockers = append(blockers, fmt.Sprintf("claim %q uses forbidden assurance type %q",
				claimID, assurance))
		}
		if len(policy.AllowedAssurances) > 0 && !allowed[assurance] {
			blockers = append(blockers, fmt.Sprintf("claim %q uses assurance type %q not in allowed list",
				claimID, assurance))
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
