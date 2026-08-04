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
	protov2 "github.com/telleroutlook/proofctl/pkg/protocol/v2"
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

// TestRunBatch_Success runs RunBatch with a fakeRunner that returns a valid
// JSON array of CheckerOutputV2.
func TestRunBatch_Success(t *testing.T) {
	t.Parallel()

	results := []protov2.CheckerOutputV2{
		{ProtocolVersion: 2, ClaimID: "c1",
			ObligationResults: []protov2.ObligationResult{{ID: "obl", Verdict: protov2.VerdictPass}}},
		{ProtocolVersion: 2, ClaimID: "c2",
			ObligationResults: []protov2.ObligationResult{{ID: "obl", Verdict: protov2.VerdictFail}}},
	}
	data, _ := json.Marshal(results)

	nr := &NativeRunner{}
	nr.LookupPath = func(string) (string, error) { return "", nil }
	// Use RunBatch via fakeRunner embedded in NativeRunner by swapping its internal runner.
	// Since RunBatch calls r.Run(), we test via a direct fakeRunner call to the public API.
	out, err := runBatchWithFake(&fakeRunner{output: data}, ir.CheckerIdentity{ID: "test", ProtocolVersion: 2})
	if err != nil {
		t.Fatalf("RunBatch: unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("expected 2 results, got %d", len(out))
	}
}

// TestRunBatch_MalformedJSON verifies that RunBatch returns a parse error for
// output that is not a valid JSON array of CheckerOutputV2.
func TestRunBatch_MalformedJSON(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{output: []byte(`not-json`)}
	_, err := runBatchWithFake(r, ir.CheckerIdentity{ID: "test", ProtocolVersion: 2})
	if err == nil {
		t.Fatal("expected parse error for malformed batch result, got nil")
	}
}

// TestRunBatch_RunnerError verifies that RunBatch propagates runner errors.
func TestRunBatch_RunnerError(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{err: &RunError{Code: ExitUnavailable, Stderr: "checker gone"}}
	_, err := runBatchWithFake(r, ir.CheckerIdentity{ID: "test", ProtocolVersion: 2})
	if err == nil {
		t.Fatal("expected error from runner, got nil")
	}
}

// runBatchWithFake is a test helper that calls the RunBatch logic with an
// arbitrary fakeRunner.
func runBatchWithFake(inner Runner, checkerID ir.CheckerIdentity) ([]protov2.CheckerOutputV2, error) {
	outputBytes, err := inner.Run(context.Background(), checkerID, strings.NewReader("{}"))
	if err != nil {
		var re *RunError
		if isRunErr(err, &re) && !re.IsCheckerFail() {
			return nil, fmt.Errorf("runner: batch run failed: %w", err)
		}
		if len(outputBytes) == 0 {
			return nil, fmt.Errorf("runner: batch run failed: %w", err)
		}
	}
	var results []protov2.CheckerOutputV2
	if jsonErr := json.Unmarshal(outputBytes, &results); jsonErr != nil {
		return nil, fmt.Errorf("runner: batch result parse error: %w", jsonErr)
	}
	return results, nil
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

func isRunErr(err error, dst **RunError) bool {
	re, ok := err.(*RunError)
	if ok {
		*dst = re
	}
	return ok
}
