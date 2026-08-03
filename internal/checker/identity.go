// Package checker provides checker identity pinning and cache-key derivation.
package checker

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// cacheKeyInput is a deterministic representation of all inputs to a checker invocation.
// Every field change must produce a different cache key.
type cacheKeyInput struct {
	ClaimID           string                  `json:"claim_id"`
	ClaimKind         string                  `json:"claim_kind"`
	StatementDigest   string                  `json:"statement_digest"`
	DependencyIDs     []string                `json:"dependency_ids"`
	DependencyDigests []string                `json:"dependency_digests"`
	Evidence          []ir.EvidenceDescriptor `json:"evidence"`
	Checker           ir.CheckerIdentity      `json:"checker"`
	SchemaDigest      string                  `json:"schema_digest"`
	PolicyDigest      string                  `json:"policy_digest"`
}

// CacheKey computes a deterministic SHA256 cache key over all inputs to a checker
// invocation. Any change to any input field produces a different key.
//
// The key is returned as a hex string (no algorithm prefix).
func CacheKey(
	claim *ir.Claim,
	deps []*ir.Claim,
	evidence []ir.EvidenceDescriptor,
	checker ir.CheckerIdentity,
	schemaDigest string,
	policyDigest string,
) string {
	depIDs := make([]string, len(deps))
	depDigests := make([]string, len(deps))
	for i, d := range deps {
		depIDs[i] = d.ID
		depDigests[i] = d.Statement.Digest
	}

	input := cacheKeyInput{
		ClaimID:           claim.ID,
		ClaimKind:         claim.Kind,
		StatementDigest:   claim.Statement.Digest,
		DependencyIDs:     depIDs,
		DependencyDigests: depDigests,
		Evidence:          evidence,
		Checker:           checker,
		SchemaDigest:      schemaDigest,
		PolicyDigest:      policyDigest,
	}

	data, err := json.Marshal(input)
	if err != nil {
		// json.Marshal on a plain struct should never fail.
		panic(fmt.Sprintf("checker: cache key marshal: %v", err))
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}
