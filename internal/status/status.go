// Package status computes the global status projection over the proof claim graph.
package status

import (
	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// Compute derives the ir.Status for every claim in the graph based on attestations.
//
// Rules (applied in this order):
//  1. If a claim has an attestation, its outcome drives the status.
//  2. If any transitive dependency is StatusDisproved, the claim is StatusBlocked.
//  3. If any transitive dependency is StatusRejected or StatusError, the claim is StatusBlocked.
//  4. If the claim has no attestation and no blocking deps, it is StatusOpen.
func Compute(graph *dag.DAG, attestations map[string]*ir.Attestation) map[string]ir.Status {
	result := make(map[string]ir.Status)

	for _, c := range graph.Claims() {
		result[c.ID] = computeOne(c.ID, graph, attestations)
	}
	return result
}

func computeOne(id string, graph *dag.DAG, attestations map[string]*ir.Attestation) ir.Status {
	// If we have a direct attestation, derive its status.
	if att, ok := attestations[id]; ok {
		return deriveStatus(att)
	}

	// Check transitive dependencies for blocking statuses.
	closure, err := graph.Closure(id)
	if err != nil {
		return ir.StatusError
	}

	for _, depID := range closure {
		depAtt, hasDep := attestations[depID]
		if !hasDep {
			continue
		}
		switch deriveStatus(depAtt) {
		case ir.StatusDisproved, ir.StatusRejected, ir.StatusError:
			return ir.StatusBlocked
		}
	}

	return ir.StatusOpen
}

// deriveStatus returns the ir.Status for an attestation.
// For v2 attestations (ProtocolVersion == 2) it re-derives status from
// ObligationResults, ignoring the writable Outcome field (Milestone 37 P0).
func deriveStatus(att *ir.Attestation) ir.Status {
	if att.Checker.ProtocolVersion == 2 {
		if len(att.ObligationResults) == 0 {
			return ir.StatusRejected
		}
		for _, r := range att.ObligationResults {
			if r.Verdict != "pass" {
				return ir.StatusRejected
			}
		}
		return ir.StatusAccepted
	}
	return ir.Status(att.Outcome)
}
