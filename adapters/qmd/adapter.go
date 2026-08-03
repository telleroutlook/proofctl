// Package qmd implements the QMD (Quantitative Mathematical Document) adapter
// for the ProofGraph Engine. It maps QMD structured output to ProofGraph IR.
package qmd

import (
	"fmt"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// QMDAdapter maps QMD structured output to ProofGraph IR.
type QMDAdapter struct {
	// Version is the QMD format version this adapter handles.
	Version string
}

// Compile parses a QMD source document and returns a ProofGraph.
// This is a stub implementation; the full parser is not yet implemented.
func (a *QMDAdapter) Compile(src []byte) (*ir.ProofGraph, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("qmd: empty source")
	}
	// TODO: implement QMD claim graph parsing.
	return nil, fmt.Errorf("qmd: Compile not yet implemented")
}
