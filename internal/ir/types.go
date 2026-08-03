// Package ir defines the Intermediate Representation types for the ProofGraph Engine.
// All types are designed for strict JSON decoding; unknown fields are rejected.
package ir

import (
	"fmt"
	"regexp"
	"strings"
)

// claimIDRe matches claim IDs that contain only safe characters: alphanumeric,
// underscore, hyphen, and dot. This prevents path traversal attacks when claim
// IDs are used in file names.
var claimIDRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// ValidateClaimID returns an error if id is empty, contains characters outside
// [a-zA-Z0-9_.-], starts with '.', or contains '..'.
// This prevents path traversal attacks when claim IDs are joined to file paths.
func ValidateClaimID(id string) error {
	if id == "" {
		return fmt.Errorf("ir: empty claim ID")
	}
	if !claimIDRe.MatchString(id) {
		return fmt.Errorf("ir: claim ID %q contains invalid characters (allowed: a-z A-Z 0-9 _ . -)", id)
	}
	if strings.HasPrefix(id, ".") {
		return fmt.Errorf("ir: claim ID %q must not start with '.'", id)
	}
	if strings.Contains(id, "..") {
		return fmt.Errorf("ir: claim ID %q must not contain '..'", id)
	}
	return nil
}

// Claim represents a single mathematical claim in the proof graph.
type Claim struct {
	ID                string    `json:"id"`
	Kind              string    `json:"kind"`
	Statement         Statement `json:"statement"`
	DependsOn         []string  `json:"depends_on"`
	RequiredAssurance []string  `json:"required_assurance"`
	Evidence          []string  `json:"evidence"` // digest refs
	CheckerPolicy     string    `json:"checker_policy"`
	// BatchGroup, if non-empty, groups claims that must be verified together by
	// a single batch checker invocation. All claims in the same group must share
	// the same checker_policy.
	BatchGroup string `json:"batch_group,omitempty"`
}

// Statement holds the human-readable text and its content-addressed digest.
type Statement struct {
	Text   string `json:"text"`
	Digest string `json:"digest"` // sha256:...
}

// EvidenceDescriptor identifies a piece of evidence by content address.
type EvidenceDescriptor struct {
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	PathHint  string `json:"path_hint,omitempty"`
}

// CheckerIdentity pins a checker to exact digest + runtime.
type CheckerIdentity struct {
	ID              string  `json:"id"`
	ProtocolVersion int     `json:"protocol_version"`
	CheckerDigest   string  `json:"checker_digest"`
	SchemaDigest    string  `json:"schema_digest"`
	Runtime         Runtime `json:"runtime"`
	Network         string  `json:"network"`
}

// Runtime describes how a checker is executed.
type Runtime struct {
	Kind                     string   `json:"kind"`          // "oci" | "native" | "wasi"
	Cmd                      []string `json:"cmd,omitempty"` // for "native": [interpreter, script, args...]
	Digest                   string   `json:"digest,omitempty"`
	DependencyManifestDigest string   `json:"dependency_manifest_digest,omitempty"` // sha256 of lockfile (requirements.txt, go.sum, etc.)
	DependencyManifestPath   string   `json:"dependency_manifest_path,omitempty"`   // relative path to lockfile from project root
}

// Status values for a claim.
type Status string

const (
	StatusOpen      Status = "open"
	StatusBlocked   Status = "blocked"
	StatusAccepted  Status = "accepted"
	StatusRejected  Status = "rejected"
	StatusError     Status = "error"
	StatusDisproved Status = "disproved"
	StatusAbandoned Status = "abandoned"
)

// Assurance types — never collapsed into a single score.
// Each type represents a distinct epistemic category.
type Assurance string

const (
	AssuranceFormalKernel            Assurance = "formal-kernel"
	AssuranceDeterministicCAP        Assurance = "deterministic-cap"
	AssuranceExactReplay             Assurance = "exact-replay"
	AssuranceReproducibleComputation Assurance = "reproducible-computation"
	AssuranceIndependentReview       Assurance = "independent-review"
	AssuranceAIReview                Assurance = "ai-review"
	AssuranceAssumption              Assurance = "assumption"
)

// Attestation records a single local verification decision.
type Attestation struct {
	ClaimID           string               `json:"claim_id"`
	StatementDigest   string               `json:"statement_digest"`
	DependencyDigests []string             `json:"dependency_digests"`
	Evidence          []EvidenceDescriptor `json:"evidence"`
	Checker           CheckerIdentity      `json:"checker"`
	Outcome           string               `json:"outcome"`
	Assurance         Assurance            `json:"assurance"`
	ErrorCode         string               `json:"error_code,omitempty"`
	BlockReason       string               `json:"block_reason,omitempty"`
	Resources         ResourceStats        `json:"resources"`
	StartFreshness    string               `json:"start_freshness"`
	EndFreshness      string               `json:"end_freshness"`
	SelfDigest        string               `json:"self_digest"`
	CacheKey          string               `json:"cache_key,omitempty"`
	Metadata          map[string]string    `json:"metadata,omitempty"`
	// Toolchain records the checker's tool version map, populated from
	// CheckerOutput.Toolchain. Stored for auditing and status --verbose display.
	Toolchain map[string]string `json:"toolchain,omitempty"`
	Signature *AttestationSig   `json:"signature,omitempty"`
}

// AttestationSig is the optional Ed25519 signature embedded in an attestation.
type AttestationSig struct {
	PubkeyFingerprint string `json:"pubkey_fingerprint"`
	Algorithm         string `json:"algorithm"`
	Value             string `json:"value"` // base64-encoded signature bytes
}

// ResourceStats captures resource consumption for a single checker invocation.
type ResourceStats struct {
	WallMillis int64 `json:"wall_millis"`
	CPUMillis  int64 `json:"cpu_millis"`
	MemBytes   int64 `json:"mem_bytes"`
}

// ProofGraph is the top-level container for a compiled proof graph.
type ProofGraph struct {
	Claims   []Claim              `json:"claims"`
	Checkers []CheckerIdentity    `json:"checkers"`
	Evidence []EvidenceDescriptor `json:"evidence"`
}
