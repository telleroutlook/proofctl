// Package runner provides the checker runner interface and implementations.
package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/telleroutlook/proofctl/internal/ir"
	protov2 "github.com/telleroutlook/proofctl/pkg/protocol/v2"
)

// Runner invokes a checker and returns its output.
type Runner interface {
	Run(ctx context.Context, checkerID ir.CheckerIdentity, input io.Reader) (output []byte, err error)
}

// Exit code constants matching the checker protocol.
const (
	ExitPass          = 0 // checker ran, claim holds
	ExitFail          = 1 // checker ran, claim does not hold
	ExitUnavailable   = 2 // checker could not run (missing deps, config error)
	ExitProtocolError = 3 // checker violated the protocol (bad output format, etc.)
)

// Resource limit constants.
const (
	MaxOutputBytes = 16 * 1024 * 1024 // 16 MB
	MaxStderrBytes = 64 * 1024        // 64 KB
	MaxWallClock   = 10 * time.Minute
)

// RuntimeAssuranceDevelopmentUnisolated marks checkers run via NativeRunner.
// This assurance type must never appear in a release attestation.
const RuntimeAssuranceDevelopmentUnisolated = "development-unisolated"

// RunError captures a structured checker failure with an exit code.
type RunError struct {
	Code    int
	Stderr  string
	Wrapped error
}

func (e *RunError) Error() string {
	msg := fmt.Sprintf("runner: exit code %d", e.Code)
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	if e.Wrapped != nil {
		msg += ": " + e.Wrapped.Error()
	}
	return msg
}

func (e *RunError) Unwrap() error { return e.Wrapped }

// IsCheckerFail reports whether the checker ran and the claim does not hold.
func (e *RunError) IsCheckerFail() bool { return e.Code == ExitFail }

// IsUnavailable reports whether the checker could not run.
func (e *RunError) IsUnavailable() bool { return e.Code == ExitUnavailable }

// IsProtocolError reports whether the checker violated the protocol.
func (e *RunError) IsProtocolError() bool { return e.Code == ExitProtocolError }

// NativeRunner runs a checker as a subprocess on the local machine.
// It is intended for development and testing only; its runtime assurance is
// RuntimeAssuranceDevelopmentUnisolated.
type NativeRunner struct {
	// LookupPath controls how the checker binary is found.
	// If nil, exec.LookPath is used.
	LookupPath func(id string) (string, error)
	// Timeout overrides the default wall-clock timeout. Zero means DefaultTimeout.
	Timeout time.Duration
	// Env, if non-nil, sets the subprocess environment instead of inheriting
	// the current process environment. Used in tests to inject helper-process
	// guards without spawning unrelated subprocesses.
	Env []string
	// ProjectRoot, if non-empty, is used as the base for resolving relative
	// paths in Runtime.Cmd entries. ${VAR} placeholders are expanded via
	// os.Getenv before path resolution.
	ProjectRoot string
}

// DefaultTimeout is the default wall-clock timeout for NativeRunner.
const DefaultTimeout = 5 * time.Minute

// Run invokes the checker as a subprocess.
// Input is passed on stdin; stdout is captured as output.
func (r *NativeRunner) Run(ctx context.Context, checkerID ir.CheckerIdentity, input io.Reader) ([]byte, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout > MaxWallClock {
		timeout = MaxWallClock
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	lookup := r.LookupPath
	if lookup == nil {
		lookup = exec.LookPath
	}

	// Determine the command to run.
	// If Runtime.Cmd is set, use it directly (Cmd[0] is the interpreter,
	// Cmd[1:] are the script and any fixed args).
	// Otherwise fall back to looking up checkerID.ID as a binary.
	var argv []string
	var digestTarget string // file whose digest is verified
	if len(checkerID.Runtime.Cmd) > 0 {
		resolved, err := r.resolveCmdPaths(checkerID.Runtime.Cmd)
		if err != nil {
			return nil, &RunError{
				Code:    ExitUnavailable,
				Stderr:  err.Error(),
				Wrapped: err,
			}
		}
		argv = resolved
		// Verify digest of the last element (the script), not the interpreter.
		digestTarget = argv[len(argv)-1]
	} else {
		binPath, err := lookup(checkerID.ID)
		if err != nil {
			return nil, &RunError{
				Code:    ExitUnavailable,
				Stderr:  fmt.Sprintf("checker %q not found", checkerID.ID),
				Wrapped: err,
			}
		}
		argv = []string{binPath}
		digestTarget = binPath
	}

	if err := verifyBinaryDigest(digestTarget, checkerID.CheckerDigest); err != nil {
		return nil, &RunError{
			Code:    ExitUnavailable,
			Stderr:  err.Error(),
			Wrapped: err,
		}
	}

	if err := verifySchemaDigest(r.ProjectRoot, checkerID); err != nil {
		return nil, &RunError{
			Code:    ExitUnavailable,
			Stderr:  err.Error(),
			Wrapped: err,
		}
	}

	//nolint:gosec // argv is resolved from pinned CheckerIdentity, not user input.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = input
	if r.Env != nil {
		cmd.Env = r.Env
	}

	// Cap stdout at MaxOutputBytes+1 to detect overflow.
	var stdoutBuf limitedBuffer
	stdoutBuf.limit = MaxOutputBytes + 1
	var stderrBuf limitedBuffer
	stderrBuf.limit = MaxStderrBytes
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	runErr := cmd.Run()

	stderrStr := stderrBuf.String()

	if runErr != nil {
		// Context deadline exceeded → unavailable.
		if ctx.Err() != nil {
			return nil, &RunError{
				Code:    ExitUnavailable,
				Stderr:  fmt.Sprintf("checker %q timed out after %v", checkerID.ID, timeout),
				Wrapped: ctx.Err(),
			}
		}

		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			code := exitErr.ExitCode()
			switch code {
			case ExitFail, ExitUnavailable, ExitProtocolError:
				return nil, &RunError{Code: code, Stderr: stderrStr, Wrapped: runErr}
			default:
				// Unknown exit code — treat as protocol error.
				return nil, &RunError{
					Code:    ExitProtocolError,
					Stderr:  stderrStr,
					Wrapped: fmt.Errorf("checker %q exited with unexpected code %d: %w", checkerID.ID, code, runErr),
				}
			}
		}
		return nil, &RunError{Code: ExitUnavailable, Stderr: fmt.Sprintf("checker %q: %v", checkerID.ID, runErr), Wrapped: runErr}
	}

	out := stdoutBuf.Bytes()

	// Cap check.
	if len(out) > MaxOutputBytes {
		return nil, &RunError{
			Code:   ExitProtocolError,
			Stderr: stderrStr,
			Wrapped: fmt.Errorf("checker %q output too large (%d bytes, limit %d bytes = %d MB)",
				checkerID.ID, len(out), MaxOutputBytes, MaxOutputBytes/(1024*1024)),
		}
	}

	// Validate stdout is valid JSON.
	if !json.Valid(out) {
		sample := out
		if len(sample) > 256 {
			sample = sample[:256]
		}
		return nil, &RunError{
			Code:   ExitProtocolError,
			Stderr: stderrStr,
			Wrapped: fmt.Errorf("checker %q produced non-JSON output (first %d bytes): %q",
				checkerID.ID, len(sample), sample),
		}
	}

	return out, nil
}

// limitedBuffer is a bytes.Buffer that stops writing after limit bytes.
type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		return len(p), nil // silently discard
	}
	if len(p) > remaining {
		// Write only up to the limit; report full len(p) to satisfy io.Writer contract.
		if _, err := b.Buffer.Write(p[:remaining]); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// resolveCmdPaths expands ${VAR} placeholders and resolves relative paths in
// a Runtime.Cmd slice. The first element (interpreter) is resolved via exec.LookPath
// if it contains no path separator; subsequent elements that are not flags (not
// starting with '-') are resolved relative to ProjectRoot when they are not absolute.
func (r *NativeRunner) resolveCmdPaths(cmd []string) ([]string, error) {
	out := make([]string, len(cmd))
	for i, elem := range cmd {
		// Expand ${VAR} and $VAR placeholders.
		expanded := os.Expand(elem, os.Getenv)
		if i == 0 {
			// Interpreter: if it contains no separator, leave for exec to resolve.
			out[i] = expanded
		} else {
			// Script / arg: resolve relative paths against ProjectRoot.
			if r.ProjectRoot != "" && expanded != "" && !strings.HasPrefix(expanded, "-") && !filepath.IsAbs(expanded) {
				abs := filepath.Join(r.ProjectRoot, expanded)
				if _, err := os.Stat(abs); err != nil {
					return nil, fmt.Errorf("runner: cmd[%d]: path %q not found (root: %s)", i, expanded, r.ProjectRoot)
				}
				expanded = abs
			}
			out[i] = expanded
		}
	}
	return out, nil
}

// verifyBinaryDigest computes the SHA256 digest of the file at path and
// compares it to expectedDigest. A zero digest (all-zeros, dev placeholder)
// is allowed without verification. An empty expectedDigest is also allowed.
// Any mismatch returns an error whose message contains "digest mismatch".
func verifyBinaryDigest(path, expectedDigest string) error {
	if expectedDigest == "" || expectedDigest == "sha256:"+strings.Repeat("0", 64) {
		// Zero digest = development placeholder — warn but allow in dev mode.
		// NativeRunner is already marked development-unisolated so this is consistent.
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("runner: open checker binary for digest check: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("runner: hash checker binary: %w", err)
	}
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if got != expectedDigest {
		return fmt.Errorf("runner: checker binary digest mismatch: want %s got %s", expectedDigest, got)
	}
	return nil
}

// verifySchemaDigest checks the schema file digest recorded in checkerID.SchemaDigest
// against the file at checkerID.Runtime.SchemaPath. A zero or empty SchemaDigest is
// treated as a development placeholder and skipped. SchemaPath is resolved relative to
// projectRoot when it is not absolute.
func verifySchemaDigest(projectRoot string, checkerID ir.CheckerIdentity) error {
	expected := checkerID.SchemaDigest
	if expected == "" || expected == "sha256:"+strings.Repeat("0", 64) {
		return nil
	}
	schemaPath := checkerID.Runtime.SchemaPath
	if schemaPath == "" {
		return nil // no schema path recorded — skip verification
	}
	if projectRoot != "" && !filepath.IsAbs(schemaPath) {
		schemaPath = filepath.Join(projectRoot, schemaPath)
	}
	f, err := os.Open(schemaPath)
	if err != nil {
		return fmt.Errorf("runner: open schema file for digest check %q: %w", schemaPath, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("runner: hash schema file %q: %w", schemaPath, err)
	}
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if got != expected {
		return fmt.Errorf("runner: schema digest mismatch for %q: want %s got %s — re-run 'proofctl pin checker --schema %s' to update",
			schemaPath, expected, got, schemaPath)
	}
	return nil
}

// RunBatch invokes the checker once for a group of claims and returns one
// CheckerOutputV2 per claim. The batch input is sent as a single JSON array;
// the checker must produce a JSON array of CheckerOutputV2 objects on stdout.
//
// This is used when ir.Claim.BatchGroup is set.
func (r *NativeRunner) RunBatch(
	ctx context.Context,
	checkerID ir.CheckerIdentity,
	input io.Reader,
) ([]protov2.CheckerOutputV2, error) {
	outputBytes, err := r.Run(ctx, checkerID, input)
	if err != nil {
		var re *RunError
		if !errors.As(err, &re) || !re.IsCheckerFail() || len(outputBytes) == 0 {
			return nil, fmt.Errorf("runner: batch run failed: %w", err)
		}
	}

	// Try to parse as a JSON array of CheckerOutputV2.
	var results []protov2.CheckerOutputV2
	if jsonErr := json.Unmarshal(outputBytes, &results); jsonErr != nil {
		return nil, fmt.Errorf("runner: checker %q batch result parse error: %w", checkerID.ID, jsonErr)
	}
	return results, nil
}
