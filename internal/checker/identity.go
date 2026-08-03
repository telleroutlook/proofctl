// Package checker provides checker identity pinning and cache-key derivation.
package checker

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"

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

// checkerDigestRe matches a valid sha256 digest: "sha256:" followed by exactly
// 64 lowercase hexadecimal characters.
var checkerDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// zeroCheckerDigest is the all-zeros development placeholder digest.
const zeroCheckerDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// allowedNetworks is the set of valid network values for a CheckerIdentity.
var allowedNetworks = map[string]bool{
	"none": true,
	"host": true,
	"":     true,
}

// Validate checks that id is a well-formed CheckerIdentity.
// It returns nil for development/shadow checkers that carry a zero digest.
// Non-zero digests must match the sha256:<64hex> format.
func Validate(id ir.CheckerIdentity) error {
	if id.ID == "" {
		return fmt.Errorf("checker: identity ID must not be empty")
	}
	if id.ProtocolVersion <= 0 {
		return fmt.Errorf("checker: protocol_version must be > 0, got %d", id.ProtocolVersion)
	}
	if !allowedNetworks[id.Network] {
		return fmt.Errorf("checker: network %q is not allowed (must be one of: none, host, empty)", id.Network)
	}
	// Allow zero digest (dev/shadow placeholder) and empty digest.
	if id.CheckerDigest == "" || id.CheckerDigest == zeroCheckerDigest {
		return nil
	}
	if !checkerDigestRe.MatchString(id.CheckerDigest) {
		return fmt.Errorf("checker: checker_digest %q has invalid format (want sha256:<64 hex chars>)", id.CheckerDigest)
	}
	return nil
}
