// Package weil implements the Weil claim graph adapter for the ProofGraph Engine.
// It maps Weil Phase B output to ProofGraph IR.
package weil

import (
	"fmt"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// WeilAdapter maps Weil Phase B output to ProofGraph IR.
// Weil Phase B produces a structured claim graph describing the mathematical
// proof of the main radius theorem; this adapter translates that representation
// into the canonical ProofGraph IR understood by proofctl.
type WeilAdapter struct {
	// Version is the Weil Phase B output format version this adapter handles.
	Version string
}

// Compile parses a Weil Phase B source document and returns a ProofGraph.
// This is a stub implementation; the full parser is not yet implemented.
func (a *WeilAdapter) Compile(src []byte) (*ir.ProofGraph, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("weil: empty source")
	}
	// TODO: implement Weil Phase B claim graph parsing.
	return nil, fmt.Errorf("weil: Compile not yet implemented")
}
