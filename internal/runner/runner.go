// Package runner provides the checker runner interface and implementations.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// Runner invokes a checker and returns its output.
type Runner interface {
	Run(ctx context.Context, checkerID ir.CheckerIdentity, input io.Reader) (output []byte, err error)
}

// RuntimeAssurance labels the assurance level of the runner environment.
const (
	// RuntimeAssuranceDevelopmentUnisolated marks checkers run via NativeRunner.
	// This assurance type must never appear in a release attestation.
	RuntimeAssuranceDevelopmentUnisolated = "development-unisolated"
)

// NativeRunner runs a checker as a subprocess on the local machine.
// It is intended for development and testing only; its runtime assurance is
// RuntimeAssuranceDevelopmentUnisolated.
//
// The checker binary is resolved by its ID field.
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
// The checker must exit 0 for pass; any other exit code is treated as an error.
func (r *NativeRunner) Run(ctx context.Context, checkerID ir.CheckerIdentity, input io.Reader) ([]byte, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	lookup := r.LookupPath
	if lookup == nil {
		lookup = exec.LookPath
	}

	binPath, err := lookup(checkerID.ID)
	if err != nil {
		return nil, fmt.Errorf("runner: checker %q not found: %w", checkerID.ID, err)
	}

	//nolint:gosec // Native runner is dev-only; binary path is resolved via lookup.
	cmd := exec.CommandContext(ctx, binPath)
	cmd.Stdin = input
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("runner: checker %q failed: %w (stderr: %s)",
			checkerID.ID, err, stderr.String())
	}
	return stdout.Bytes(), nil
}
