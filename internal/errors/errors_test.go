package errors

import (
	"strings"
	"testing"
)

func TestNew_ErrorString(t *testing.T) {
	t.Parallel()
	e := New(CodeInvalidInput, "bad field")
	if e.Code != CodeInvalidInput {
		t.Errorf("Code: got %q want %q", e.Code, CodeInvalidInput)
	}
	if e.Message != "bad field" {
		t.Errorf("Message: got %q want %q", e.Message, "bad field")
	}
	got := e.Error()
	if !strings.Contains(got, CodeInvalidInput) || !strings.Contains(got, "bad field") {
		t.Errorf("Error() = %q, want code and message present", got)
	}
}

func TestNew_WithDetail(t *testing.T) {
	t.Parallel()
	e := &ProofError{Code: CodeDigestMismatch, Message: "mismatch", Detail: "want X got Y"}
	got := e.Error()
	if !strings.Contains(got, "want X got Y") {
		t.Errorf("Error() = %q, want detail present", got)
	}
}

func TestNew_WithoutDetail(t *testing.T) {
	t.Parallel()
	e := New(CodeCheckerFailed, "checker died")
	got := e.Error()
	if strings.Contains(got, "(") {
		t.Errorf("Error() = %q, detail parens should be absent when Detail is empty", got)
	}
}

func TestNewf_FormatsMessage(t *testing.T) {
	t.Parallel()
	e := Newf(CodeMissingDependency, "claim %q missing dep %q", "A", "B")
	if !strings.Contains(e.Message, "claim") || !strings.Contains(e.Message, "A") {
		t.Errorf("Newf message = %q, want formatted string", e.Message)
	}
	if e.Code != CodeMissingDependency {
		t.Errorf("Code: got %q want %q", e.Code, CodeMissingDependency)
	}
}

func TestProofError_ImplementsError(t *testing.T) {
	t.Parallel()
	var _ error = New(CodeOK, "")
}

func TestAllCodesDefined(t *testing.T) {
	t.Parallel()
	codes := []string{
		CodeOK, CodeInvalidInput, CodeUnknownField, CodeDuplicateID,
		CodeCycleDetected, CodeMissingDependency, CodeMissingEvidence,
		CodeDigestMismatch, CodeSizeMismatch, CodeCheckerNotFound,
		CodeCheckerFailed, CodePolicyViolation, CodeFreshnessViolation,
		CodeReleaseBlocked, CodeInternalError, CodeNotImplemented,
	}
	for _, c := range codes {
		if c == "" {
			t.Error("found empty error code constant")
		}
	}
}
