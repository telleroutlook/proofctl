// Package smt implements the SMT/Alethe/DRAT proof adapter for proofctl.
// It uses the same 3-claim DAG pattern as the LRAT adapter:
//
//	def-<id>-formula  → lem-<id>-unsat → thm-<id>-verified
package smt

import (
	"fmt"
	"strings"

	"github.com/telleroutlook/proofctl/internal/ir"
)

const (
	checkerID      = "smt-checker-v1"
	SMT2MediaType  = "application/x-smt2"
	ProofMediaType = "application/x-smt-proof"
	zeroDigest     = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

// Format identifies the SMT proof format.
type Format string

const (
	FormatAlethe Format = "alethe"
	FormatDRAT   Format = "drat"
)

// ProblemSpec describes an SMT verification problem.
type ProblemSpec struct {
	// ProblemID is the unique identifier (used as claim ID prefix).
	ProblemID string `json:"problem_id"`
	// Description is a human-readable description.
	Description string `json:"description"`
	// Format is the proof certificate format: "alethe" or "drat".
	Format Format `json:"format"`
	// SMT2Digest is the sha256 digest of the .smt2 file.
	SMT2Digest string `json:"smt2_digest"`
	// SMT2Size is the size of the .smt2 file.
	SMT2Size int64 `json:"smt2_size"`
	// ProofDigest is the sha256 digest of the proof certificate.
	ProofDigest string `json:"proof_digest"`
	// ProofSize is the size of the proof certificate.
	ProofSize int64 `json:"proof_size"`
}

// SMTAdapter compiles SMT proof problems into ProofGraph IR.
type SMTAdapter struct{}

// Compile converts an SMT ProblemSpec into a 3-claim ProofGraph.
func (a *SMTAdapter) Compile(spec ProblemSpec) (*ir.ProofGraph, error) {
	if spec.ProblemID == "" {
		return nil, fmt.Errorf("smt adapter: empty problem ID")
	}
	if strings.ContainsAny(spec.ProblemID, " /\\:") {
		return nil, fmt.Errorf("smt adapter: problem ID contains invalid characters")
	}
	if spec.Format != FormatAlethe && spec.Format != FormatDRAT {
		return nil, fmt.Errorf("smt adapter: unsupported format %q (want: alethe, drat)", spec.Format)
	}

	formulaID := "def-" + spec.ProblemID + "-formula"
	unsatID := "lem-" + spec.ProblemID + "-unsat"
	thmID := "thm-" + spec.ProblemID + "-verified"

	formulaText := fmt.Sprintf("SMT-LIB2 formula %s.", spec.ProblemID)
	unsatText := fmt.Sprintf("Formula %s is unsatisfiable.", spec.ProblemID)
	thmText := fmt.Sprintf("%s certificate verifies UNSAT for %s.", strings.ToUpper(string(spec.Format)), spec.ProblemID)

	smt2Ev := ir.EvidenceDescriptor{
		MediaType: SMT2MediaType,
		Digest:    spec.SMT2Digest,
		Size:      spec.SMT2Size,
		PathHint:  spec.ProblemID + ".smt2",
	}
	proofEv := ir.EvidenceDescriptor{
		MediaType: ProofMediaType,
		Digest:    spec.ProofDigest,
		Size:      spec.ProofSize,
		PathHint:  spec.ProblemID + "." + string(spec.Format),
	}

	claims := []ir.Claim{
		{
			ID:            formulaID,
			Kind:          "definition",
			Statement:     ir.Statement{Text: formulaText, Digest: ir.StatementDigest(formulaText)},
			DependsOn:     []string{},
			Evidence:      []string{smt2Ev.Digest},
			CheckerPolicy: "",
		},
		{
			ID:            unsatID,
			Kind:          "lemma",
			Statement:     ir.Statement{Text: unsatText, Digest: ir.StatementDigest(unsatText)},
			DependsOn:     []string{formulaID},
			Evidence:      []string{smt2Ev.Digest, proofEv.Digest},
			CheckerPolicy: checkerID,
		},
		{
			ID:            thmID,
			Kind:          "theorem",
			Statement:     ir.Statement{Text: thmText, Digest: ir.StatementDigest(thmText)},
			DependsOn:     []string{formulaID, unsatID},
			Evidence:      []string{proofEv.Digest},
			CheckerPolicy: checkerID,
		},
	}

	checker := ir.CheckerIdentity{
		ID:              checkerID,
		ProtocolVersion: 1,
		CheckerDigest:   zeroDigest,
		Runtime: ir.Runtime{
			Kind: "native",
			Cmd:  []string{"python3", "${PROOFCTL_ADAPTERS}/smt/bridge.py", "--format", string(spec.Format)},
		},
	}

	return &ir.ProofGraph{
		Claims:   claims,
		Checkers: []ir.CheckerIdentity{checker},
		Evidence: []ir.EvidenceDescriptor{smt2Ev, proofEv},
	}, nil
}
