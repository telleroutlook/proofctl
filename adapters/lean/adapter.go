// Package lean implements the Lean 4 theorem prover adapter for the ProofGraph Engine.
// It maps Lean 4 proof export output to ProofGraph IR.
package lean

import (
	"fmt"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// LeanAdapter maps Lean 4 proof export output to ProofGraph IR.
type LeanAdapter struct {
	// Version is the Lean 4 export format version this adapter handles.
	Version string
}

// Compile parses a Lean 4 proof export document and returns a ProofGraph.
// This is a stub implementation; the full parser is not yet implemented.
func (a *LeanAdapter) Compile(src []byte) (*ir.ProofGraph, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("lean: empty source")
	}
	// TODO: implement Lean 4 proof export parsing.
	return nil, fmt.Errorf("lean: Compile not yet implemented")
}
