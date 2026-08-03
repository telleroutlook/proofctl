package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// zeroDigest is the all-zeros dev-placeholder digest.
const zeroDigest = "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000"

// computeFileDigest computes the sha256 digest of the file at path, returning
// it in "sha256:<hex>" form.
func computeFileDigest(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("computeFileDigest: open %s: %v", path, err)
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 32*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// realBinaryPath returns the path to a binary that exists on disk for use
// as a fake checker path. We use the test binary itself.
func realBinaryPath(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return exe
}

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
	// Use a digest that is syntactically valid but wrong.
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

// newNativeRunnerWithFixed returns a NativeRunner whose LookupPath always
// resolves to the given fixed path (bypassing PATH lookup).
func newNativeRunnerWithFixed(fixedPath string) *NativeRunner {
	return &NativeRunner{
		LookupPath: func(_ string) (string, error) {
			return fixedPath, nil
		},
	}
}

// checkerID builds a CheckerIdentity with the given id and digest.
func checkerID(id, digest string) ir.CheckerIdentity {
	return ir.CheckerIdentity{
		ID:              id,
		ProtocolVersion: 1,
		CheckerDigest:   digest,
	}
}

// TestNativeRunner_DigestMatch verifies that when the binary digest matches,
// the runner proceeds past the digest check. The binary won't be a valid
// checker, so we expect a protocol-level error (not a digest mismatch error).
func TestNativeRunner_DigestMatch(t *testing.T) {
	t.Parallel()
	path := realBinaryPath(t)
	digest := computeFileDigest(t, path)

	r := newNativeRunnerWithFixed(path)
	_, err := r.Run(context.Background(), checkerID("test-checker", digest), nil)

	// The binary is not a real checker, so we expect some error — but not a
	// digest mismatch error.
	if err != nil {
		if strings.Contains(err.Error(), "digest mismatch") {
			t.Errorf("unexpected digest mismatch error (digest should match): %v", err)
		}
		// Any other error (ExitProtocolError, ExitUnavailable from the binary's
		// exit code, etc.) is acceptable — the point is the digest check passed.
	}
	// err == nil is also acceptable if the binary happens to exit 0 with valid JSON.
}

// TestNativeRunner_DigestMismatch verifies that when the binary digest does
// not match, the runner returns a RunError containing "digest mismatch".
func TestNativeRunner_DigestMismatch(t *testing.T) {
	t.Parallel()
	path := realBinaryPath(t)
	// A syntactically valid but incorrect digest (not all-zeros, so not a dev placeholder).
	wrongDigest := "sha256:" + strings.Repeat("b", 64)

	r := newNativeRunnerWithFixed(path)
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
// placeholder digest does not trigger a mismatch error.
func TestNativeRunner_ZeroDigest_Allowed(t *testing.T) {
	t.Parallel()
	path := realBinaryPath(t)

	r := newNativeRunnerWithFixed(path)
	_, err := r.Run(context.Background(), checkerID("test-checker", zeroDigest), nil)

	// The binary is not a real checker, so we expect some error — but not a
	// digest mismatch error.
	if err != nil && strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("zero digest should be allowed (dev mode), got: %v", err)
	}
}

// isRunError attempts to type-assert err to *RunError and writes the result
// into dst. Returns true if successful.
func isRunError(err error, dst **RunError) bool {
	re, ok := err.(*RunError)
	if ok {
		*dst = re
	}
	return ok
}
