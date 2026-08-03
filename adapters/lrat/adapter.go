// Package lrat implements the LRAT SAT proof adapter for the ProofGraph Engine.
// It maps LRAT proof certificates to ProofGraph IR claims, demonstrating
// second-domain generality without modifying the core IR or release gate.
package lrat

import (
	"fmt"
	"strings"

	lratdomain "github.com/telleroutlook/proofctl/internal/lrat"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// Adapter compiles LRAT problem descriptions into ProofGraph IR.
type Adapter struct{}

// ProblemSpec describes an LRAT verification problem.
type ProblemSpec struct {
	// ProblemID is the unique identifier for this SAT problem.
	ProblemID string `json:"problem_id"`
	// Description is a human-readable problem description.
	Description string `json:"description"`
	// CNFDigest is the sha256 digest of the DIMACS CNF file.
	CNFDigest string `json:"cnf_digest"`
	// CNFSize is the size in bytes of the CNF file.
	CNFSize int64 `json:"cnf_size"`
	// LRATDigest is the sha256 digest of the LRAT certificate file.
	LRATDigest string `json:"lrat_digest"`
	// LRATSize is the size in bytes of the LRAT certificate.
	LRATSize int64 `json:"lrat_size"`
	// NumVariables is the number of Boolean variables in the formula.
	NumVariables int `json:"num_variables"`
	// NumClauses is the number of clauses in the CNF formula.
	NumClauses int `json:"num_clauses"`
}

// Compile converts an LRAT ProblemSpec into a ProofGraph with 3 claims:
//  1. def-<problemID>-formula: the CNF formula definition
//  2. lem-<problemID>-unsat: claims the formula is unsatisfiable
//  3. thm-<problemID>-verified: the LRAT checker verified the proof
//
// The resulting ProofGraph uses the same IR as the Weil adapter —
// demonstrating that the core model is domain-agnostic.
func (a *Adapter) Compile(spec ProblemSpec) (*ir.ProofGraph, error) {
	if spec.ProblemID == "" {
		return nil, fmt.Errorf("lrat adapter: empty problem ID")
	}
	if strings.ContainsAny(spec.ProblemID, " /\\:") {
		return nil, fmt.Errorf("lrat adapter: problem ID contains invalid characters")
	}

	formulaID := "def-" + spec.ProblemID + "-formula"
	unsatID := "lem-" + spec.ProblemID + "-unsat"
	thmID := "thm-" + spec.ProblemID + "-verified"

	formulaText := fmt.Sprintf("CNF formula %s: %d variables, %d clauses.",
		spec.ProblemID, spec.NumVariables, spec.NumClauses)
	unsatText := fmt.Sprintf("The CNF formula %s is unsatisfiable.", spec.ProblemID)
	thmText := fmt.Sprintf("LRAT certificate verifies UNSAT for formula %s.", spec.ProblemID)

	cnfEvidence := ir.EvidenceDescriptor{
		MediaType: lratdomain.CNFMediaType,
		Digest:    spec.CNFDigest,
		Size:      spec.CNFSize,
		PathHint:  spec.ProblemID + ".cnf",
	}
	lratEvidence := ir.EvidenceDescriptor{
		MediaType: lratdomain.CertificateMediaType,
		Digest:    spec.LRATDigest,
		Size:      spec.LRATSize,
		PathHint:  spec.ProblemID + ".lrat",
	}

	claims := []ir.Claim{
		{
			ID:   formulaID,
			Kind: lratdomain.KindCNFFormula,
			Statement: ir.Statement{
				Text:   formulaText,
				Digest: ir.StatementDigest(formulaText),
			},
			DependsOn:         []string{},
			RequiredAssurance: []string{string(ir.AssuranceExactReplay)},
			Evidence:          []string{cnfEvidence.Digest},
			CheckerPolicy:     "",
		},
		{
			ID:   unsatID,
			Kind: lratdomain.KindUNSATClaim,
			Statement: ir.Statement{
				Text:   unsatText,
				Digest: ir.StatementDigest(unsatText),
			},
			DependsOn:         []string{formulaID},
			RequiredAssurance: []string{string(ir.AssuranceDeterministicCAP)},
			Evidence:          []string{cnfEvidence.Digest, lratEvidence.Digest},
			CheckerPolicy:     lratdomain.CheckerPolicyID,
		},
		{
			ID:   thmID,
			Kind: lratdomain.KindLRATVerified,
			Statement: ir.Statement{
				Text:   thmText,
				Digest: ir.StatementDigest(thmText),
			},
			DependsOn:         []string{formulaID, unsatID},
			RequiredAssurance: []string{string(ir.AssuranceDeterministicCAP)},
			Evidence:          []string{lratEvidence.Digest},
			CheckerPolicy:     lratdomain.CheckerPolicyID,
		},
	}

	evidence := []ir.EvidenceDescriptor{cnfEvidence, lratEvidence}
	checkers := []ir.CheckerIdentity{lratdomain.LRATCheckerID}

	return &ir.ProofGraph{
		Claims:   claims,
		Checkers: checkers,
		Evidence: evidence,
	}, nil
}
