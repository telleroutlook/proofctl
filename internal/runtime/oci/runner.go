// Package oci provides the OCIRunner for executing checkers in isolated OCI containers.
//
// OCIRunner implements the runner.Runner interface. The actual OCI container
// execution is not yet implemented (returns ErrNotImplemented). This skeleton
// establishes the interface boundary so that other packages can reference
// OCIRunner in type assertions and policy checks.
//
// Full OCI implementation is planned for M26+.
package oci

import (
	"context"
	"errors"
	"io"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// ErrNotImplemented is returned by OCIRunner until full OCI support lands.
var ErrNotImplemented = errors.New("oci: OCI runner not yet implemented (planned M26+)")

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
	// non-zero before Run is called.
	ImageDigest string

	// Network specifies the container network mode. Must be "none" for release-eligible runs.
	Network string

	// CASRoot is the local path to the CAS store used for evidence materialization.
	CASRoot string
}

// Run executes the checker inside an OCI container.
// Returns ErrNotImplemented until full OCI support is available.
func (r *OCIRunner) Run(_ context.Context, _ ir.CheckerIdentity, _ io.Reader) ([]byte, error) {
	return nil, ErrNotImplemented
}
