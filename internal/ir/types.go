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
	// CrossDomainDeps lists claim IDs from other domains whose attestations must
	// already be accepted before this claim can be verified.
	// Used when a Lean/Coq claim relies on a numerically-verified CAP claim.
	CrossDomainDeps []string `json:"cross_domain_deps,omitempty"`
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
	// SchemaPath is the relative path (from project root) to the JSON Schema file
	// whose digest is recorded in CheckerIdentity.SchemaDigest. Used by the runner
	// to verify schema integrity before each checker invocation.
	SchemaPath string `json:"schema_path,omitempty"`
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

// AssuranceLevel returns the ordinal rank of an assurance type, where higher
// numbers mean stronger evidence. Returns 0 for unknown types (treated as lowest).
// Used to detect downgrade attempts when overwriting an attestation.
func AssuranceLevel(a Assurance) int {
	switch a {
	case AssuranceFormalKernel:
		return 6
	case AssuranceDeterministicCAP:
		return 5
	case AssuranceExactReplay:
		return 4
	case AssuranceReproducibleComputation:
		return 3
	case AssuranceIndependentReview:
		return 2
	case AssuranceAIReview:
		return 1
	default:
		return 0
	}
}

// Attestation records a single local verification decision.
//
// v1 only: Outcome and Assurance are writable fields that a checker or human
// can set directly. The v2 release path (proofverify) must NOT read these fields
// to determine claim state — it re-derives state from the identity closure via
// internal/kernel/derive. The v2 release path now reads ObligationResults
// from the attestation instead of trusting this field (P0 fix, Milestone 37).
type Attestation struct {
	ClaimID           string               `json:"claim_id"`
	StatementDigest   string               `json:"statement_digest"`
	DependencyDigests []string             `json:"dependency_digests"`
	Evidence          []EvidenceDescriptor `json:"evidence"`
	Checker           CheckerIdentity      `json:"checker"`
	Outcome           string               `json:"outcome"`   // v1 only; v2 release path must not consume this field
	Assurance         Assurance            `json:"assurance"` // v1 only; v2 release path must not consume this field
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
	// ReplayMode records how the certificate was verified:
	// "from_scratch" means the generator was re-run from scratch and the output
	// digest was compared against the pinned evidence (set by proofctl replay).
	// "self_consistency" means the checker ran against already-imported CAS evidence
	// without re-running the generator (set by proofctl check).
	// Empty for attestations written before this field was introduced.
	ReplayMode string `json:"replay_mode,omitempty"`
	// ObligationResults stores the per-obligation verdicts from the v2 checker output.
	// Present only for v2 attestations (Checker.ProtocolVersion == 2).
	// The release gate reads this field instead of the writable Outcome field to
	// determine acceptance — a hand-crafted "outcome":"accepted" cannot bypass C01.
	ObligationResults []ObligationResult `json:"obligation_results,omitempty"`
	Signature         *AttestationSig    `json:"signature,omitempty"`
}

// ObligationResult mirrors protov2.ObligationResult for storage in ir.Attestation.
// Kept in ir so the kernel package has no dependency on pkg/protocol.
type ObligationResult struct {
	ID            string `json:"id"`
	Verdict       string `json:"verdict"` // "pass" | "fail"
	WitnessDigest string `json:"witness_digest,omitempty"`
	Method        string `json:"method,omitempty"`
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
