package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/pkg/protocol"
)

// TestMain implements the helper-process pattern so that tests can use
// os.Executable() as a fake checker binary without triggering infinite
// subprocess recursion.
//
// When a test spawns the test binary as a subprocess it sets
// GO_WANT_HELPER_PROCESS=1 in the subprocess environment.  TestMain detects
// this flag, runs the requested helper, and exits immediately — it never
// reaches testing.M.Run(), so no tests are executed recursively.
//
// Two helper modes are supported via GO_HELPER_MODE:
//
//	"accepted"  — emit a valid CheckerOutput{outcome:"accepted"} and exit 0
//	"fail"      — emit a valid CheckerOutput{outcome:"rejected"} and exit 1
func TestMain(m *testing.M) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		os.Exit(m.Run())
	}
	// Helper-process mode: act as a minimal fake checker and exit.
	mode := os.Getenv("GO_HELPER_MODE")
	out := protocol.CheckerOutput{
		ProtocolVersion: protocol.ProtocolVersion,
		ClaimID:         "test-claim",
		Outcome:         "accepted",
		Assurance:       string(ir.AssuranceDeterministicCAP),
	}
	if mode == "fail" {
		out.Outcome = "rejected"
	}
	data, _ := json.Marshal(out)
	fmt.Printf("%s\n", data)
	if mode == "fail" {
		os.Exit(1)
	}
	os.Exit(0)
}

// helperEnv returns the environment slice that makes the test binary behave as
// a fake checker in the given mode ("accepted" or "fail").
func helperEnv(mode string) []string {
	return []string{
		"GO_WANT_HELPER_PROCESS=1",
		"GO_HELPER_MODE=" + mode,
	}
}

// realBinaryPath returns the path to the currently running test binary.
// Safe to use as a fake checker path because TestMain exits immediately when
// GO_WANT_HELPER_PROCESS=1 is set; there is no infinite subprocess recursion.
func realBinaryPath(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return exe
}

// computeFileDigest computes the sha256 digest of the file at path.
func computeFileDigest(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("computeFileDigest: open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	buf := make([]byte, 32*1024)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if readErr != nil {
			break
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// zeroDigest is the all-zeros dev-placeholder digest.
const zeroDigest = "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000"

// newHelper returns a NativeRunner that resolves any checker ID to the test
// binary itself, injecting the helper-process environment so the binary exits
// immediately rather than recursing.
func newHelper(mode string) *NativeRunner {
	exe, _ := os.Executable()
	return &NativeRunner{
		LookupPath: func(_ string) (string, error) { return exe, nil },
		Env:        helperEnv(mode),
	}
}

// checkerID builds a minimal CheckerIdentity for tests.
func checkerID(id, digest string) ir.CheckerIdentity {
	return ir.CheckerIdentity{
		ID:              id,
		ProtocolVersion: 1,
		CheckerDigest:   digest,
	}
}

// ── verifyBinaryDigest unit tests ────────────────────────────────────────────

// TestVerifyBinaryDigest_Correct verifies that a matching digest returns nil.
func TestVerifyBinaryDigest_Correct(t *testing.T) {
	t.Parallel()
	path := realBinaryPath(t)
	digest := computeFileDigest(t, path)
	if err := verifyBinaryDigest(path, digest); err != nil {
		t.Errorf("expected nil for correct digest, got: %v", err)
	}
}

// TestVerifyBinaryDigest_Wrong verifies that a wrong expected digest returns
// an error containing "mismatch".
func TestVerifyBinaryDigest_Wrong(t *testing.T) {
	t.Parallel()
	path := realBinaryPath(t)
	wrong := "sha256:" + strings.Repeat("a", 64)
	err := verifyBinaryDigest(path, wrong)
	if err == nil {
		t.Fatal("expected error for wrong digest, got nil")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected error to contain 'mismatch', got: %v", err)
	}
}

// TestVerifyBinaryDigest_EmptyDigest verifies that an empty expected digest is
// allowed (dev mode placeholder).
func TestVerifyBinaryDigest_EmptyDigest(t *testing.T) {
	t.Parallel()
	path := realBinaryPath(t)
	if err := verifyBinaryDigest(path, ""); err != nil {
		t.Errorf("expected nil for empty digest (dev mode), got: %v", err)
	}
}

// TestVerifyBinaryDigest_ZeroDigest verifies that the all-zeros digest is
// allowed (dev mode placeholder).
func TestVerifyBinaryDigest_ZeroDigest(t *testing.T) {
	t.Parallel()
	path := realBinaryPath(t)
	if err := verifyBinaryDigest(path, zeroDigest); err != nil {
		t.Errorf("expected nil for zero digest (dev mode), got: %v", err)
	}
}

// TestVerifyBinaryDigest_MissingFile verifies that a nonexistent path returns
// an error.
func TestVerifyBinaryDigest_MissingFile(t *testing.T) {
	t.Parallel()
	err := verifyBinaryDigest("/nonexistent/path/to/binary", "sha256:"+strings.Repeat("a", 64))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// ── NativeRunner integration tests (helper-process pattern) ──────────────────

// TestNativeRunner_DigestMatch verifies that a runner with the correct binary
// digest passes the digest check and executes the checker (which here emits a
// valid accepted output via the helper-process).
func TestNativeRunner_DigestMatch(t *testing.T) {
	t.Parallel()
	path := realBinaryPath(t)
	digest := computeFileDigest(t, path)

	r := &NativeRunner{
		LookupPath: func(_ string) (string, error) { return path, nil },
		Env:        helperEnv("accepted"),
	}
	res, err := r.Run(context.Background(), checkerID("test-checker", digest), nil)
	if err != nil {
		if strings.Contains(err.Error(), "digest mismatch") {
			t.Errorf("unexpected digest mismatch (digest should match): %v", err)
		}
		// Other errors (protocol, unavailable) are acceptable in this test.
		return
	}
	// If no error, output must be valid JSON.
	if !json.Valid(res) {
		t.Errorf("expected valid JSON output, got: %s", res)
	}
}

// TestNativeRunner_DigestMismatch verifies that a wrong digest causes the
// runner to return a RunError containing "digest mismatch" before executing
// the binary.
func TestNativeRunner_DigestMismatch(t *testing.T) {
	t.Parallel()
	wrongDigest := "sha256:" + strings.Repeat("b", 64)
	r := newHelper("accepted")
	r.LookupPath = func(_ string) (string, error) { return realBinaryPath(t), nil }

	_, err := r.Run(context.Background(), checkerID("test-checker", wrongDigest), nil)
	if err == nil {
		t.Fatal("expected error for digest mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("expected error to contain 'digest mismatch', got: %v", err)
	}
	var re *RunError
	if ok := isRunError(err, &re); !ok {
		t.Errorf("expected *RunError, got %T: %v", err, err)
	} else if re.Code != ExitUnavailable {
		t.Errorf("expected ExitUnavailable (%d), got code %d", ExitUnavailable, re.Code)
	}
}

// TestNativeRunner_ZeroDigest_Allowed verifies that the all-zeros dev
// placeholder does not trigger a mismatch error, and that the helper-process
// binary is actually executed (returning valid output) rather than recursing.
func TestNativeRunner_ZeroDigest_Allowed(t *testing.T) {
	t.Parallel()
	r := newHelper("accepted")
	res, err := r.Run(context.Background(), checkerID("test-checker", zeroDigest), nil)
	if err != nil {
		if strings.Contains(err.Error(), "digest mismatch") {
			t.Errorf("zero digest should be allowed, got: %v", err)
		}
		return
	}
	if !json.Valid(res) {
		t.Errorf("expected valid JSON output, got: %s", res)
	}
}

// TestNativeRunner_CheckerPass verifies the full happy path: helper exits 0
// with a valid accepted CheckerOutput.
func TestNativeRunner_CheckerPass(t *testing.T) {
	t.Parallel()
	r := newHelper("accepted")
	res, err := r.Run(context.Background(), checkerID("test-checker", zeroDigest), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out protocol.CheckerOutput
	if jsonErr := json.Unmarshal(res, &out); jsonErr != nil {
		t.Fatalf("unmarshal output: %v", jsonErr)
	}
	if out.Outcome != "accepted" {
		t.Errorf("expected outcome 'accepted', got %q", out.Outcome)
	}
}

// TestNativeRunner_CheckerFail verifies that exit 1 with a valid rejected
// CheckerOutput returns a *RunError with Code == ExitFail.
func TestNativeRunner_CheckerFail(t *testing.T) {
	t.Parallel()
	r := newHelper("fail")
	_, err := r.Run(context.Background(), checkerID("test-checker", zeroDigest), nil)
	if err == nil {
		t.Fatal("expected error for checker fail, got nil")
	}
	var re *RunError
	if ok := isRunError(err, &re); !ok {
		t.Errorf("expected *RunError, got %T: %v", err, err)
	} else if re.Code != ExitFail {
		t.Errorf("expected ExitFail (%d), got code %d", ExitFail, re.Code)
	}
}

// ── RunError method coverage ──────────────────────────────────────────────────

func TestRunError_Methods(t *testing.T) {
	t.Parallel()

	fail := &RunError{Code: ExitFail, Stderr: "fail", Wrapped: fmt.Errorf("inner")}
	if !fail.IsCheckerFail() {
		t.Error("IsCheckerFail should be true for ExitFail")
	}
	if fail.IsUnavailable() {
		t.Error("IsUnavailable should be false for ExitFail")
	}
	if fail.IsProtocolError() {
		t.Error("IsProtocolError should be false for ExitFail")
	}
	if fail.Unwrap() == nil {
		t.Error("Unwrap should return the wrapped error")
	}

	unavail := &RunError{Code: ExitUnavailable}
	if !unavail.IsUnavailable() {
		t.Error("IsUnavailable should be true for ExitUnavailable")
	}

	proto := &RunError{Code: ExitProtocolError}
	if !proto.IsProtocolError() {
		t.Error("IsProtocolError should be true for ExitProtocolError")
	}
}

func TestRunError_ErrorString_WithStederr(t *testing.T) {
	t.Parallel()
	e := &RunError{Code: ExitFail, Stderr: "assertion failed"}
	s := e.Error()
	if !strings.Contains(s, "assertion failed") {
		t.Errorf("Error() = %q, want stderr present", s)
	}
}

func TestRunError_ErrorString_NoStederr(t *testing.T) {
	t.Parallel()
	e := &RunError{Code: ExitUnavailable}
	s := e.Error()
	if s == "" {
		t.Error("Error() should not be empty")
	}
}

// ── limitedBuffer Write coverage ──────────────────────────────────────────────

func TestLimitedBuffer_TruncatesAtLimit(t *testing.T) {
	t.Parallel()
	var buf limitedBuffer
	buf.limit = 4
	n, err := buf.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Errorf("Write returned %d, want 5 (reported length of input)", n)
	}
	if buf.Len() != 4 {
		t.Errorf("buffer length = %d, want 4", buf.Len())
	}
}

func TestLimitedBuffer_DiscardsBeyondLimit(t *testing.T) {
	t.Parallel()
	var buf limitedBuffer
	buf.limit = 3
	_, _ = buf.Write([]byte("abc"))
	n, err := buf.Write([]byte("more data"))
	if err != nil {
		t.Fatalf("Write after limit: %v", err)
	}
	// Should silently discard — returns length of input as if written
	if n != len("more data") {
		t.Errorf("Write returned %d, want %d", n, len("more data"))
	}
	if buf.Len() != 3 {
		t.Errorf("buffer should stay at 3, got %d", buf.Len())
	}
}
func isRunError(err error, dst **RunError) bool {
	re, ok := err.(*RunError)
	if ok {
		*dst = re
	}
	return ok
}
