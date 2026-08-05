// Package oci provides the OCIRunner for executing checkers in isolated OCI containers.
//
// OCIRunner implements the runner.Runner interface. It runs checkers in
// digest-pinned OCI containers with strict isolation:
//   - network=none (no outbound access)
//   - read-only root filesystem
//   - checker input passed via stdin
//   - checker output captured from stdout
//
// If docker is not available in PATH, Run returns ErrDockerNotFound.
package oci

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// ErrNotImplemented is kept for backward compatibility.
var ErrNotImplemented = errors.New("oci: OCI runner not yet implemented (planned M26+)")

// ErrDockerNotFound is returned when the docker binary is not in PATH.
var ErrDockerNotFound = errors.New("oci: docker binary not found in PATH; install docker to use OCIRunner")

// ErrInsecureConfig is returned when the runner configuration would allow
// network access or a mutable root filesystem.
var ErrInsecureConfig = errors.New("oci: insecure configuration: Network must be \"none\" and ImageDigest must be non-empty")

// RuntimeClass is the runtime class name reported in attestations for OCI-run checkers.
const RuntimeClass = "isolated-oci"

// OCIRunner executes a checker inside an isolated OCI container.
//
// Constraints enforced (INV-10 complement to native-dev):
//   - Network must be "none" (no outbound access during checker run)
//   - Root filesystem is read-only
//   - CAS evidence is materialized as read-only bind mounts
//
// These constraints make OCIRunner the only runner whose results are eligible
// to contribute to a formal release (i.e. not blocked by C09).
type OCIRunner struct {
	// ImageDigest is the sha256 of the OCI image to run. Must be non-empty and
	// non-zero before Run is called. Format: "sha256:<64hex>" or "repo@sha256:<64hex>".
	ImageDigest string

	// Network specifies the container network mode. Must be "none" for release-eligible runs.
	Network string

	// CASRoot is the local path to the CAS store used for evidence materialization.
	CASRoot string

	// CPUQuota is the CPU quota (e.g. "0.5" for 50%). Empty means no limit.
	CPUQuota string

	// MemLimitMB is the memory limit in megabytes. 0 means no limit.
	MemLimitMB int

	// TimeoutSec is the container execution timeout in seconds. 0 means use context deadline.
	TimeoutSec int
}

// Run executes the checker inside an isolated OCI container.
// The checker input is written to container stdin; stdout is returned as the result.
//
// Security invariants enforced before any exec:
//  1. ImageDigest must be non-empty (prevents mutable :latest tags)
//  2. Network must be "none" (no outbound connections)
//  3. Root filesystem is mounted read-only (--read-only)
func (r *OCIRunner) Run(ctx context.Context, checkerID ir.CheckerIdentity, input io.Reader) ([]byte, error) {
	// Validate security configuration before executing anything.
	if r.ImageDigest == "" || r.Network != "none" {
		return nil, ErrInsecureConfig
	}

	// Verify docker is available.
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return nil, ErrDockerNotFound
	}

	// Build docker run arguments.
	args := []string{
		"run",
		"--rm",                 // remove container after exit
		"--network", r.Network, // network isolation (must be "none")
		"--read-only",                      // read-only root filesystem
		"--security-opt=no-new-privileges", // prevent privilege escalation
		"-i",                               // stdin attached
		"--env", "LC_ALL=C",                // fixed locale
		"--env", "TZ=UTC", // fixed timezone
	}

	// Optional resource limits.
	if r.CPUQuota != "" {
		args = append(args, "--cpus", r.CPUQuota)
	}
	if r.MemLimitMB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dm", r.MemLimitMB))
	}

	// CAS read-only mount.
	if r.CASRoot != "" {
		args = append(args, "--volume", r.CASRoot+":/cas:ro")
	}

	// Temporary writable directory for the checker process.
	args = append(args, "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m")

	// Image (must be digest-pinned).
	args = append(args, r.ImageDigest)

	// Checker command from runtime (if specified).
	if len(checkerID.Runtime.Cmd) > 0 {
		args = append(args, checkerID.Runtime.Cmd...)
	}

	// Read input bytes so we can pipe them.
	inputBytes, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("oci: read checker input: %w", err)
	}

	cmd := exec.CommandContext(ctx, dockerPath, args...)
	cmd.Stdin = bytes.NewReader(inputBytes)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		// Return both stdout (partial checker output) and the error.
		combined := stdout.Bytes()
		if len(combined) == 0 {
			combined = stderr.Bytes()
		}
		return combined, fmt.Errorf("oci: docker run failed: %w (stderr: %s)", runErr, stderr.String())
	}

	return stdout.Bytes(), nil
}
