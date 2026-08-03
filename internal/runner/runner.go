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
	"strings"
	"time"

	"github.com/telleroutlook/proofctl/internal/ir"
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
	MaxOutputBytes = 16 * 1024 * 1024  // 16 MB
	MaxStderrBytes = 64 * 1024         // 64 KB
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

	binPath, err := lookup(checkerID.ID)
	if err != nil {
		return nil, &RunError{
			Code:    ExitUnavailable,
			Stderr:  fmt.Sprintf("checker %q not found", checkerID.ID),
			Wrapped: err,
		}
	}

	if err := verifyBinaryDigest(binPath, checkerID.CheckerDigest); err != nil {
		return nil, &RunError{
			Code:    ExitUnavailable,
			Stderr:  err.Error(),
			Wrapped: err,
		}
	}

	//nolint:gosec // Native runner is dev-only; binary path is resolved via lookup.
	cmd := exec.CommandContext(ctx, binPath)
	cmd.Stdin = input

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
				Stderr:  "timeout",
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
		return nil, &RunError{Code: ExitUnavailable, Stderr: stderrStr, Wrapped: runErr}
	}

	out := stdoutBuf.Bytes()

	// Cap check.
	if len(out) > MaxOutputBytes {
		return nil, &RunError{
			Code:   ExitProtocolError,
			Stderr: stderrStr,
			Wrapped: fmt.Errorf("checker %q output too large (%d bytes)", checkerID.ID, len(out)),
		}
	}

	// Validate stdout is valid JSON.
	if !json.Valid(out) {
		return nil, &RunError{
			Code:    ExitProtocolError,
			Stderr:  stderrStr,
			Wrapped: fmt.Errorf("checker %q produced non-JSON output", checkerID.ID),
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
	remaining := b.limit - b.Buffer.Len()
	if remaining <= 0 {
		return len(p), nil // silently discard
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	return b.Buffer.Write(p)
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
	defer f.Close()
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
