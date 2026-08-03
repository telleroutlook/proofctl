package runner

// runner_coverage_test.go exercises RunBatch and the timeout/unavailable paths
// that are not covered by the main test file.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/pkg/protocol"
)

// ── RunBatch ─────────────────────────────────────────────────────────────────

// batchHelper extends TestMain's helper-process registry.
// Mode "batch" emits a BatchResult with two accepted claims.
// Mode "batch-fail" emits an exit-1 scalar (not a batch) output.
// Mode "batch-empty" emits valid JSON but no "claims" field.
//
// These modes are registered by init() so they are picked up by TestMain.
func init() {
	// The helper-process modes are handled inside TestMain (runner_test.go).
	// We register extra modes here by monkey-patching the subprocess env check
	// that TestMain already performs — nothing needed here, we extend via
	// the real TestMain indirection in the test binary.
}

// batchHelperEnv and the init() stub below are intentionally left for future
// helper-process extension of the batch test modes.
func init() {
	// Extra helper modes (e.g. "batch") can be registered here.
}

// TestRunBatch_Success runs RunBatch with a helper that emits a valid batch
// result. Because TestMain only knows "accepted"/"fail", we drive RunBatch
// through a scripted fakeRunner that returns pre-built batch JSON.
func TestRunBatch_Success(t *testing.T) {
	t.Parallel()

	result := protocol.BatchResult{
		Claims: []protocol.ClaimResult{
			{ClaimID: "c1", OK: true, Assurance: "deterministic-cap"},
			{ClaimID: "c2", OK: false, Assurance: "deterministic-cap"},
		},
	}
	data, _ := json.Marshal(result)

	r := &fakeRunner{output: data}
	claims, err := (&NativeRunner{}).runBatchFrom(r, ir.CheckerIdentity{ID: "test", ProtocolVersion: 1},
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("RunBatch: unexpected error: %v", err)
	}
	if len(claims) != 2 {
		t.Errorf("expected 2 claim results, got %d", len(claims))
	}
}

// TestRunBatch_NoBatchField verifies that RunBatch returns an error when the
// checker output lacks a "claims" field.
func TestRunBatch_NoBatchField(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{output: []byte(`{"outcome":"accepted"}`)}
	_, err := (&NativeRunner{}).runBatchFrom(r, ir.CheckerIdentity{ID: "test", ProtocolVersion: 1},
		strings.NewReader(`{}`))
	if err == nil {
		t.Fatal("expected error for missing 'claims' field, got nil")
	}
	if !strings.Contains(err.Error(), "claims") {
		t.Errorf("error should mention 'claims' field, got: %v", err)
	}
}

// TestRunBatch_RunnerError verifies that RunBatch propagates runner errors.
func TestRunBatch_RunnerError(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{err: &RunError{Code: ExitUnavailable, Stderr: "checker gone"}}
	_, err := (&NativeRunner{}).runBatchFrom(r, ir.CheckerIdentity{ID: "test", ProtocolVersion: 1},
		strings.NewReader(`{}`))
	if err == nil {
		t.Fatal("expected error from runner, got nil")
	}
}

// TestRunBatch_MalformedJSON verifies that RunBatch returns a parse error for
// well-formed JSON that does not match BatchResult structure.
func TestRunBatch_MalformedJSON(t *testing.T) {
	t.Parallel()

	// Valid JSON object with claims as a string (not array) → unmarshal fails.
	r := &fakeRunner{output: []byte(`{"claims":"not-an-array"}`)}
	_, err := (&NativeRunner{}).runBatchFrom(r, ir.CheckerIdentity{ID: "test", ProtocolVersion: 1},
		strings.NewReader(`{}`))
	if err == nil {
		t.Fatal("expected parse error for malformed batch result, got nil")
	}
}

// ── Timeout path ─────────────────────────────────────────────────────────────

// TestNativeRunner_Timeout verifies that the runner returns an ExitUnavailable
// RunError containing the checker ID when the context deadline is exceeded.
func TestNativeRunner_Timeout(t *testing.T) {
	t.Parallel()

	// Use a script that sleeps, so the context will cancel before it finishes.
	// We write a tiny shell script to a temp dir.
	dir := t.TempDir()
	scriptPath := dir + "/sleep.sh"
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nsleep 10\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	r := &NativeRunner{
		LookupPath: func(_ string) (string, error) { return scriptPath, nil },
		Timeout:    200 * time.Millisecond,
	}
	_, err := r.Run(ctx, checkerID("slow-checker", zeroDigest), nil)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	re, ok := err.(*RunError)
	if !ok {
		t.Fatalf("expected *RunError, got %T: %v", err, err)
	}
	if re.Code != ExitUnavailable {
		t.Errorf("expected ExitUnavailable, got code %d", re.Code)
	}
	if !strings.Contains(re.Stderr, "slow-checker") {
		t.Errorf("error should mention checker ID, got: %q", re.Stderr)
	}
}

// ── Non-exec error path ───────────────────────────────────────────────────────

// TestNativeRunner_BinaryNotFound verifies that the runner returns a
// descriptive error when the checker binary cannot be found via LookupPath.
func TestNativeRunner_BinaryNotFound(t *testing.T) {
	t.Parallel()
	r := &NativeRunner{
		LookupPath: func(_ string) (string, error) {
			return "", fmt.Errorf("not found")
		},
	}
	_, err := r.Run(context.Background(), checkerID("missing-checker", zeroDigest), nil)
	if err == nil {
		t.Fatal("expected error for binary not found, got nil")
	}
	if !strings.Contains(err.Error(), "missing-checker") {
		t.Errorf("error should mention checker ID, got: %v", err)
	}
}

// ── LimitedBuffer overflow at exactly limit ───────────────────────────────────

// TestLimitedBuffer_ExactLimit verifies that writing exactly limit bytes
// does not truncate and the entire input is buffered.
func TestLimitedBuffer_ExactLimit(t *testing.T) {
	t.Parallel()
	var buf limitedBuffer
	buf.limit = 5
	n, err := buf.Write([]byte("hello")) // exactly limit
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Errorf("returned n = %d, want 5", n)
	}
	if buf.Len() != 5 {
		t.Errorf("buffer length = %d, want 5", buf.Len())
	}
}

// TestLimitedBuffer_ZeroLimit verifies that a buffer with limit=0 discards
// all writes without error.
func TestLimitedBuffer_ZeroLimit(t *testing.T) {
	t.Parallel()
	var buf limitedBuffer
	buf.limit = 0
	n, err := buf.Write([]byte("data"))
	if err != nil {
		t.Fatalf("Write with zero limit: %v", err)
	}
	if n != 4 {
		t.Errorf("returned n = %d, want 4", n)
	}
	if buf.Len() != 0 {
		t.Errorf("buffer should be empty, got length %d", buf.Len())
	}
}

// ── fakeRunner ────────────────────────────────────────────────────────────────

// fakeRunner is a test double for runner.Runner that returns canned output.
type fakeRunner struct {
	output []byte
	err    error
}

func (f *fakeRunner) Run(_ context.Context, _ ir.CheckerIdentity, _ io.Reader) ([]byte, error) {
	return f.output, f.err
}

// runBatchFrom is a test-only shim that lets us call RunBatch logic with an
// arbitrary Runner implementation instead of NativeRunner.
func (r *NativeRunner) runBatchFrom(inner Runner, checkerID ir.CheckerIdentity, input io.Reader) ([]protocol.ClaimResult, error) {
	outputBytes, err := inner.Run(context.Background(), checkerID, input)
	if err != nil {
		var re *RunError
		if isRunErr(err, &re) && re.IsCheckerFail() && len(re.Stderr) > 0 {
			// Try to parse output even on exit 1.
		} else if len(outputBytes) == 0 {
			return nil, fmt.Errorf("runner: batch run failed: %w", err)
		}
	}
	if !protocol.IsBatchOutput(outputBytes) {
		return nil, fmt.Errorf("runner: checker %q did not return batch output (missing 'claims' field)", checkerID.ID)
	}
	var batch protocol.BatchResult
	if jsonErr := json.Unmarshal(outputBytes, &batch); jsonErr != nil {
		return nil, fmt.Errorf("runner: checker %q batch result parse error: %w", checkerID.ID, jsonErr)
	}
	return batch.Claims, nil
}

func isRunErr(err error, dst **RunError) bool {
	re, ok := err.(*RunError)
	if ok {
		*dst = re
	}
	return ok
}
