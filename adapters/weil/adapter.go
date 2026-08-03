// Package weil implements the Weil claim graph adapter.
// It compiles a Weil ProofGraph source into ProofGraph IR and,
// in shadow mode, annotates claims with known D-defect blockers.
package weil

import (
	"encoding/json"
	"fmt"

	"github.com/telleroutlook/proofctl/internal/ir"
	proofweil "github.com/telleroutlook/proofctl/internal/weil"
)

// Adapter compiles Weil claim graph sources into ProofGraph IR.
type Adapter struct {
	// ShadowMode enables shadow attestation generation for known D-defects.
	// In shadow mode no formal release attestation is produced.
	ShadowMode bool
}

// Compile parses src as a ProofGraph JSON and returns the IR.
// If ShadowMode is true, it also returns shadow attestations for all claims.
func (a *Adapter) Compile(src []byte) (*ir.ProofGraph, map[string]*ir.Attestation, error) {
	var graph ir.ProofGraph
	if err := json.Unmarshal(src, &graph); err != nil {
		return nil, nil, fmt.Errorf("weil adapter: parse: %w", err)
	}
	if len(graph.Claims) == 0 {
		return nil, nil, fmt.Errorf("weil adapter: no claims in source")
	}

	var attestations map[string]*ir.Attestation
	if a.ShadowMode {
		attestations = a.buildShadowAttestations(graph.Claims)
	}

	return &graph, attestations, nil
}

func (a *Adapter) buildShadowAttestations(claims []ir.Claim) map[string]*ir.Attestation {
	defects := proofweil.DefectsByClaimID()
	atts := make(map[string]*ir.Attestation, len(claims))
	for i := range claims {
		c := &claims[i]
		if defect, hasDefect := defects[c.ID]; hasDefect {
			atts[c.ID] = proofweil.BuildShadowAttestation(c, defect)
		} else {
			atts[c.ID] = proofweil.BuildOpenAttestation(c)
		}
	}
	return atts
}
