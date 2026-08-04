// Package v2 defines the stable wire types for checker protocol version 2.
//
// Key design invariant (INV-01): CheckerOutputV2 does NOT contain Outcome,
// Assurance, or any field that allows a checker to assert "accepted" or
// "released" directly. The checker only returns per-obligation verdicts.
// All claim states are derived by proofverify from these results plus the
// Contract, Policy, and identity closure — never from checker-reported status.
package v2

// ProtocolVersion is the v2 checker protocol version.
const ProtocolVersion = 2

// ObligationVerdict is the result of a single checker obligation.
type ObligationVerdict string

const (
	VerdictPass ObligationVerdict = "pass"
	VerdictFail ObligationVerdict = "fail"
)

// CheckerInputV2 is passed to a v2 checker on stdin as a single JSON object.
// The checker must not use fields outside this set to determine its behavior.
type CheckerInputV2 struct {
	ProtocolVersion int    `json:"protocol_version"`
	ClaimID         string `json:"claim_id"`

	// StatementDigest is the content-addressed digest of the canonical statement.
	StatementDigest string `json:"statement_digest"`
	// StatementText is the canonical statement text.
	StatementText string `json:"statement_text"`

	// ContractDigest is the digest of the Verification Contract for this claim.
	ContractDigest string `json:"contract_digest"`

	// DependencyAttestations maps dependency claim IDs to their
	// verified attestation digests (INV-08: deps must be at required state).
	DependencyAttestations map[string]string `json:"dependency_attestations"`

	// Evidence is the set of evidence descriptors for this invocation.
	// The checker reads evidence only from the CAS-materialized read-only paths.
	Evidence []EvidenceRefV2 `json:"evidence"`

	// ObligationIDs is the exact set of obligations this checker must resolve.
	// The checker must return results for every ID in this list — no more, no less (INV-06).
	ObligationIDs []string `json:"obligation_ids"`

	// PolicyDigest pins the policy file in effect for this invocation.
	PolicyDigest string `json:"policy_digest"`
}

// EvidenceRefV2 is a read-only reference to a CAS-materialized evidence blob.
type EvidenceRefV2 struct {
	Role      string `json:"role"`
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	// LocalPath is the read-only CAS path where the checker reads the blob.
	// It must NOT be treated as a writable path or as a canonical identity.
	LocalPath string `json:"local_path"`
}

// CheckerOutputV2 is written by a v2 checker to stdout.
//
// INV-01: This struct intentionally has no Outcome, Assurance, Status, or
// Released fields. A checker cannot assert that a claim is accepted or
// released — only that each individual obligation passed or failed.
// proofverify derives the claim state from ObligationResults plus the Contract.
//
// INV-06: The checker must return exactly one ObligationResult per obligation
// declared in CheckerInputV2.ObligationIDs. Missing, duplicate, or unknown
// obligation IDs cause proofverify to reject the output.
type CheckerOutputV2 struct {
	ProtocolVersion int    `json:"protocol_version"`
	ClaimID         string `json:"claim_id"`

	// InputClosureDigest must echo the digest of the checker's input set.
	// proofverify rejects outputs where this does not match.
	InputClosureDigest string `json:"input_closure_digest"`

	// CheckerIdentityDigest is the sha256 of the checker binary/script.
	CheckerIdentityDigest string `json:"checker_identity_digest"`

	// RuntimeIdentityDigest is the sha256 of the OCI image or runtime spec.
	RuntimeIdentityDigest string `json:"runtime_identity_digest"`

	// EvidenceUsed lists the digests of evidence actually read by this checker.
	// Must be a subset of the evidence provided in CheckerInputV2.
	EvidenceUsed []string `json:"evidence_used"`

	// ObligationResults is the per-obligation verdict list.
	// INV-06: must contain exactly the IDs declared in CheckerInputV2.ObligationIDs.
	// INV-07: if any required evidence caused a failure, the verdict must be "fail".
	ObligationResults []ObligationResult `json:"obligation_results"`

	// Toolchain records the tool versions used during verification.
	// Hashed into the identity closure so toolchain drift forces re-verification.
	Toolchain map[string]string `json:"toolchain,omitempty"`
}

// ObligationResult records the checker's verdict for one named obligation.
type ObligationResult struct {
	// ID must match one of the IDs in CheckerInputV2.ObligationIDs.
	ID string `json:"id"`

	// Verdict is "pass" or "fail". No other values are accepted.
	// INV-01: "accepted", "verified", "released" are not valid verdicts.
	Verdict ObligationVerdict `json:"verdict"`

	// WitnessDigest is the CAS digest of the typed witness produced for this
	// obligation (e.g. interval enclosure blob). Empty for pure logical obligations.
	WitnessDigest string `json:"witness_digest,omitempty"`

	// Method identifies the algorithm or proof rule used (e.g. "arb-interval-quadrature-v1").
	Method string `json:"method,omitempty"`
}

// CheckerErrorV2 is written by a v2 checker to stdout on protocol-level errors.
// The checker must exit with code 3 in this case.
type CheckerErrorV2 struct {
	ProtocolVersion int    `json:"protocol_version"`
	ClaimID         string `json:"claim_id,omitempty"`
	Code            string `json:"code"`
	Message         string `json:"message"`
}
