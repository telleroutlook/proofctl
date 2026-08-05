// Package errors defines the stable JSON error schema for all CLI and API outputs.
package errors

import "fmt"

// Error codes — stable across versions. Never reuse a code for a different meaning.
const (
	CodeOK                   = "OK"
	CodeInvalidInput         = "INVALID_INPUT"
	CodeUnknownField         = "UNKNOWN_FIELD"
	CodeDuplicateID          = "DUPLICATE_ID"
	CodeCycleDetected        = "CYCLE_DETECTED"
	CodeMissingDependency    = "MISSING_DEPENDENCY"
	CodeMissingEvidence      = "MISSING_EVIDENCE"
	CodeDigestMismatch       = "DIGEST_MISMATCH"
	CodeSizeMismatch         = "SIZE_MISMATCH"
	CodeCheckerNotFound      = "CHECKER_NOT_FOUND"
	CodeCheckerFailed        = "CHECKER_FAILED"
	CodePolicyViolation      = "POLICY_VIOLATION"
	CodeFreshnessViolation   = "FRESHNESS_VIOLATION"
	CodeReleaseBlocked       = "RELEASE_BLOCKED"
	CodeLegacyAttestation    = "LEGACY_ATTESTATION_NOT_RELEASABLE"
	CodeInternalError        = "INTERNAL_ERROR"
	CodeNotImplemented       = "NOT_IMPLEMENTED"
	CodeInputClosureMismatch = "INPUT_CLOSURE_MISMATCH"
	CodeEvidenceSetMismatch  = "EVIDENCE_SET_MISMATCH"
)

// ProofError is the stable JSON error type for all CLI and API outputs.
type ProofError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

func (e *ProofError) Error() string {
	if e.Detail != "" {
		return e.Code + ": " + e.Message + " (" + e.Detail + ")"
	}
	return e.Code + ": " + e.Message
}

// New returns a ProofError with the given code and message.
func New(code, message string) *ProofError {
	return &ProofError{Code: code, Message: message}
}

// Newf returns a ProofError with the given code and a formatted message.
func Newf(code, format string, args ...any) *ProofError {
	return &ProofError{Code: code, Message: fmt.Sprintf(format, args...)}
}
