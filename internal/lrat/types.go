// Package lrat provides types and utilities for LRAT SAT proof certificates.
// LRAT (Linear Rat) is a standard format for machine-checkable UNSAT proofs.
package lrat

import "github.com/telleroutlook/proofctl/internal/ir"

// CertificateMediaType is the media type for LRAT certificate evidence.
const CertificateMediaType = "application/vnd.lrat.certificate.v1"

// CNFMediaType is the media type for DIMACS CNF formula evidence.
const CNFMediaType = "application/vnd.dimacs.cnf.v1"

// ClaimKinds for LRAT domain.
const (
	KindCNFFormula   = "cnf-formula"   // The input CNF formula (definition)
	KindUNSATClaim   = "unsat-claim"   // Claims the formula is unsatisfiable
	KindLRATVerified = "lrat-verified" // Claim verified by LRAT checker
)

// CheckerPolicyID for the LRAT checker.
const CheckerPolicyID = "lrat-checker-v1"

// LRATCheckerID is the identity for a hypothetical LRAT checker.
// In Phase 7, this uses a native dev runner (shadow mode).
var LRATCheckerID = ir.CheckerIdentity{
	ID:              "lrat-checker-v1",
	ProtocolVersion: 2,
	CheckerDigest:   "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	SchemaDigest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	Runtime:         ir.Runtime{Kind: "native"},
	Network:         "none",
}
