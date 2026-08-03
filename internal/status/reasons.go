package status

import (
	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// ClaimStatus holds the computed status and the reason if blocked.
type ClaimStatus struct {
	Status      ir.Status
	BlockReason string // non-empty when Status is StatusBlocked
}

// ComputeWithReasons is like Compute but also returns the block reason for each blocked claim.
// When a claim is blocked because of a dependency attestation, BlockReason is set to
// that dependency's att.BlockReason, or the dep claim ID if no reason is recorded.
func ComputeWithReasons(graph *dag.DAG, attestations map[string]*ir.Attestation) map[string]ClaimStatus {
	result := make(map[string]ClaimStatus)
	for _, c := range graph.Claims() {
		result[c.ID] = computeOneWithReason(c.ID, graph, attestations)
	}
	return result
}

func computeOneWithReason(id string, graph *dag.DAG, attestations map[string]*ir.Attestation) ClaimStatus {
	// If we have a direct attestation, use its outcome (and reason if blocked).
	if att, ok := attestations[id]; ok {
		cs := ClaimStatus{Status: ir.Status(att.Outcome)}
		if cs.Status == ir.StatusBlocked {
			cs.BlockReason = att.BlockReason
		}
		return cs
	}

	// Check transitive dependencies for blocking statuses.
	closure, err := graph.Closure(id)
	if err != nil {
		return ClaimStatus{Status: ir.StatusError}
	}

	for _, depID := range closure {
		depAtt, hasDep := attestations[depID]
		if !hasDep {
			continue
		}
		switch ir.Status(depAtt.Outcome) {
		case ir.StatusDisproved, ir.StatusRejected, ir.StatusError:
			reason := depAtt.BlockReason
			if reason == "" {
				reason = depID
			}
			return ClaimStatus{Status: ir.StatusBlocked, BlockReason: reason}
		}
	}

	return ClaimStatus{Status: ir.StatusOpen}
}
