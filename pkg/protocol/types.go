// Package protocol defines the public wire types for external checker processes.
// These types are stable and versioned; breaking changes require a protocol version bump.
package protocol

import "encoding/json"

// ProtocolVersion is the version of the checker protocol this package implements.
const ProtocolVersion = 1

// CheckerInput is passed to a checker on stdin as a single JSON object.
type CheckerInput struct {
	// ProtocolVersion must match the checker's declared protocol version.
	ProtocolVersion int `json:"protocol_version"`
	// ClaimID is the identifier of the claim being checked.
	ClaimID string `json:"claim_id"`
	// StatementDigest is the content-addressed digest of the claim statement.
	StatementDigest string `json:"statement_digest"`
	// StatementText is the human-readable claim statement.
	StatementText string `json:"statement_text"`
	// DependencyDigests maps dependency claim IDs to their statement digests.
	DependencyDigests map[string]string `json:"dependency_digests"`
	// Evidence is the list of evidence descriptors available to the checker.
	Evidence []EvidenceRef `json:"evidence"`
	// PolicyDigest is the content-addressed digest of the checker policy file.
	PolicyDigest string `json:"policy_digest"`
}

// EvidenceRef is a reference to an evidence blob available to the checker.
type EvidenceRef struct {
	// MediaType is the MIME type of the evidence blob.
	MediaType string `json:"media_type"`
	// Digest is the content-addressed digest of the blob (sha256:<hex>).
	Digest string `json:"digest"`
	// Size is the byte size of the blob.
	Size int64 `json:"size"`
	// LocalPath is the path where the checker can read the blob.
	// The checker must not write to this path.
	LocalPath string `json:"local_path"`
}

// CheckerOutput is written by a checker to stdout as a single JSON object.
// The checker must exit 0 if and only if the claim is accepted.
//
// v1 only: Outcome and Assurance are writable by the checker process.
// In the v2 protocol (pkg/protocol/v2), these fields do not exist; the checker
// only returns per-obligation verdicts and proofverify derives the state.
type CheckerOutput struct {
	// ProtocolVersion must match CheckerInput.ProtocolVersion.
	ProtocolVersion int `json:"protocol_version"`
	// ClaimID must echo CheckerInput.ClaimID.
	ClaimID string `json:"claim_id"`
	// Outcome is one of "accepted", "rejected", "disproved", "error", "unavailable".
	// v1 only; v2 release path must not consume this field — use ObligationResults instead.
	Outcome string `json:"outcome"`
	// Assurance is the assurance type the checker is asserting.
	// v1 only; v2 release path must not consume this field — proofverify derives assurance.
	Assurance string `json:"assurance"`
	// Explanation is an optional human-readable explanation of the outcome.
	Explanation string `json:"explanation,omitempty"`
	// ErrorCode is set when Outcome is "error" or "unavailable".
	ErrorCode string `json:"error_code,omitempty"`
	// Metadata is an optional map of domain-specific key-value pairs that are
	// stored in the attestation. Used by release conditions (required_metadata_keys).
	Metadata map[string]string `json:"metadata,omitempty"`
	// Toolchain records the tool versions used during verification.
	// Keys are tool-specific (e.g. "lean_version", "mathlib_commit", "lake_version").
	// proofctl hashes this map and includes it in the cache key so that
	// a toolchain change forces re-verification even when all inputs are identical.
	Toolchain map[string]string `json:"toolchain,omitempty"`
	// Resources reports resource consumption.
	Resources ResourceUsage `json:"resources"`
}

// CheckerError is written by a checker to stdout when a protocol-level error occurs.
// The checker must exit 3 in this case.
type CheckerError struct {
	// ProtocolVersion must match CheckerInput.ProtocolVersion.
	ProtocolVersion int `json:"protocol_version"`
	// ClaimID echoes CheckerInput.ClaimID, if available.
	ClaimID string `json:"claim_id,omitempty"`
	// Code is a machine-readable error code.
	Code string `json:"code"`
	// Message is a human-readable error description.
	Message string `json:"message"`
}

// ResourceUsage captures resource consumption for a checker invocation.
type ResourceUsage struct {
	// WallMillis is wall-clock time in milliseconds.
	WallMillis int64 `json:"wall_millis"`
	// CPUMillis is CPU time in milliseconds.
	CPUMillis int64 `json:"cpu_millis"`
	// MemBytes is peak resident memory in bytes.
	MemBytes int64 `json:"mem_bytes"`
}

// BatchResult is written by a batch checker to stdout when a single invocation
// checks multiple claims at once (e.g. lake build, coqchk, isabelle build).
// A checker output is treated as batch mode when the root JSON object contains
// a "claims" array field; otherwise single-claim mode applies (backward compatible).
//
// Batch checkers must exit 0 only if every claim in the batch was accepted.
type BatchResult struct {
	// Claims contains one result entry per claim checked.
	Claims []ClaimResult `json:"claims"`
	// Resources reports total resource consumption for the entire batch.
	Resources ResourceUsage `json:"resources,omitempty"`
}

// ClaimResult is a single claim's outcome within a BatchResult.
type ClaimResult struct {
	// ClaimID is the identifier of the claim this result belongs to.
	ClaimID string `json:"claim_id"`
	// OK is true if the claim was accepted by the checker.
	OK bool `json:"ok"`
	// Assurance is the assurance type being asserted (e.g. "formal-kernel").
	Assurance string `json:"assurance,omitempty"`
	// Metadata is optional domain-specific key-value pairs stored in the attestation.
	Metadata map[string]string `json:"metadata,omitempty"`
	// Error is set when OK is false and the checker produced an error message.
	Error string `json:"error,omitempty"`
}

// IsBatchOutput returns true if data contains a root-level "claims" array,
// indicating the checker used batch mode output.
func IsBatchOutput(data []byte) bool {
	// Fast path: scan for the key without full parse.
	// We unmarshal only the discriminator field.
	var probe struct {
		Claims *json.RawMessage `json:"claims"`
	}
	return json.Unmarshal(data, &probe) == nil && probe.Claims != nil
}
