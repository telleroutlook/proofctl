// Package identity computes the content-addressed identity closure for a claim.
//
// ClaimIdentity is defined as:
//
//	H(canonical_statement, ordered_dep_identities, evidence_descriptors,
//	  contract_digest, checker_identity_digest, runtime_identity_digest,
//	  policy_digest, graph_root_digest)
//
// Any change to any input field produces a different identity. This identity
// is the cache key and the binding between an attestation and its inputs.
// Caching logic must use this function — separate approximate identity
// functions are forbidden (INV-09).
package identity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// EvidenceDescriptor identifies a piece of evidence by content address.
// Kept minimal here so kernel has no dependency on internal/ir.
type EvidenceDescriptor struct {
	Role      string `json:"role"`
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
}

// ClaimIdentityInputs holds every input that contributes to a claim's identity.
// All fields are included in the canonical hash; omitting any field breaks
// the closure guarantee.
type ClaimIdentityInputs struct {
	// CanonicalStatement is the normalized text of the claim being verified.
	CanonicalStatement string `json:"canonical_statement"`

	// OrderedDepIdentities contains the identity digests of direct dependencies,
	// in a deterministic order (typically sorted by claim ID).
	OrderedDepIdentities []string `json:"ordered_dep_identities"`

	// EvidenceDescriptors describes the evidence set used for this claim.
	EvidenceDescriptors []EvidenceDescriptor `json:"evidence_descriptors"`

	// ContractDigest is the sha256 of the Verification Contract JSON for this claim.
	ContractDigest string `json:"contract_digest"`

	// CheckerIdentityDigest is the sha256 of the checker binary or script.
	CheckerIdentityDigest string `json:"checker_identity_digest"`

	// RuntimeIdentityDigest is the sha256 of the OCI image or runtime spec.
	RuntimeIdentityDigest string `json:"runtime_identity_digest"`

	// PolicyDigest is the sha256 of the release policy file.
	PolicyDigest string `json:"policy_digest"`

	// GraphRootDigest is the sha256 of the proof graph root (graph.json).
	GraphRootDigest string `json:"graph_root_digest"`
}

// Compute returns the canonical identity digest for a claim given its inputs.
// The result is returned as "sha256:<64-hex-chars>".
//
// The implementation serializes inputs to canonical JSON (sorted keys,
// no trailing whitespace) and hashes the result with SHA-256. The same
// inputs always produce the same digest regardless of Go version or platform.
//
// json.Marshal on ClaimIdentityInputs (strings, string slices, simple structs)
// cannot fail; the error is suppressed intentionally.
func Compute(inputs ClaimIdentityInputs) string {
	data, _ := json.Marshal(inputs) // ClaimIdentityInputs contains only JSON-marshallable types
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}

// MustCompute is identical to Compute. It exists for callers that prefer
// an explicit "must succeed" name at call sites.
func MustCompute(inputs ClaimIdentityInputs) string {
	return Compute(inputs)
}
