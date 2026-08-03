package weil

import (
	"github.com/telleroutlook/proofctl/internal/ir"
)

// ShadowCheckerID is the synthetic checker identity used for shadow attestations.
// It is explicitly marked as not satisfying any release assurance requirement.
var ShadowCheckerID = ir.CheckerIdentity{
	ID:              "weil-shadow-v0",
	ProtocolVersion: 0,
	CheckerDigest:   "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	SchemaDigest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	Runtime:         ir.Runtime{Kind: "shadow"},
	Network:         "none",
}

// ShadowAssurance is the assurance type for shadow attestations.
// This assurance type is always in the forbidden list for formal release.
const ShadowAssurance ir.Assurance = "shadow-review"

// BuildShadowAttestation creates a blocked attestation for a claim that has a known defect.
// The attestation records the D-number and block reason but cannot satisfy release policy.
func BuildShadowAttestation(claim *ir.Claim, defect Defect) *ir.Attestation {
	return &ir.Attestation{
		ClaimID:         claim.ID,
		StatementDigest: claim.Statement.Digest,
		Checker:         ShadowCheckerID,
		Outcome:         string(ir.StatusBlocked),
		Assurance:       ShadowAssurance,
		BlockReason:     defect.BlockReason,
		ErrorCode:       "POLICY_VIOLATION",
		Resources:       ir.ResourceStats{},
	}
}

// BuildOpenAttestation creates an open (unattested) shadow record for claims without known defects.
// These claims still need real checker attestations before release.
func BuildOpenAttestation(claim *ir.Claim) *ir.Attestation {
	return &ir.Attestation{
		ClaimID:         claim.ID,
		StatementDigest: claim.Statement.Digest,
		Checker:         ShadowCheckerID,
		Outcome:         string(ir.StatusOpen),
		Assurance:       ShadowAssurance,
		ErrorCode:       "",
		BlockReason:     "no formal attestation — shadow mode only",
	}
}
