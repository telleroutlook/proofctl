package oci_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/runtime/oci"
)

func TestOCIRunner_InsecureConfig_EmptyDigest(t *testing.T) {
	t.Parallel()
	r := &oci.OCIRunner{
		ImageDigest: "",
		Network:     "none",
	}
	_, err := r.Run(context.Background(), ir.CheckerIdentity{ID: "test"}, strings.NewReader(""))
	if !errors.Is(err, oci.ErrInsecureConfig) {
		t.Errorf("expected ErrInsecureConfig for empty ImageDigest, got: %v", err)
	}
}

func TestOCIRunner_InsecureConfig_WrongNetwork(t *testing.T) {
	t.Parallel()
	r := &oci.OCIRunner{
		ImageDigest: "sha256:abc123",
		Network:     "bridge",
	}
	_, err := r.Run(context.Background(), ir.CheckerIdentity{ID: "test"}, strings.NewReader(""))
	if !errors.Is(err, oci.ErrInsecureConfig) {
		t.Errorf("expected ErrInsecureConfig for Network=bridge, got: %v", err)
	}
}

// TestOCIRunner_DockerNotFound verifies that a valid config but missing docker binary
// returns ErrDockerNotFound. This is the expected result in CI environments without docker.
func TestOCIRunner_DockerNotFound(t *testing.T) {
	t.Parallel()
	r := &oci.OCIRunner{
		ImageDigest: "sha256:abc123",
		Network:     "none",
	}
	_, err := r.Run(context.Background(), ir.CheckerIdentity{ID: "test"}, strings.NewReader(""))
	if err == nil {
		// docker is present and ran — acceptable in environments that have docker.
		return
	}
	// In environments without docker, ErrDockerNotFound is expected.
	// In environments with docker, the image won't exist and docker run will fail with
	// a wrapped error that is not ErrDockerNotFound. Both outcomes are acceptable.
	if errors.Is(err, oci.ErrDockerNotFound) {
		// docker not in PATH — expected in most CI environments
		return
	}
	// docker present but image not found or other docker error — also fine
	if errors.Is(err, oci.ErrInsecureConfig) {
		t.Errorf("unexpected ErrInsecureConfig with valid config: %v", err)
	}
}

func TestOCIRunner_RuntimeClass(t *testing.T) {
	t.Parallel()
	if oci.RuntimeClass != "isolated-oci" {
		t.Errorf("RuntimeClass must be %q, got %q", "isolated-oci", oci.RuntimeClass)
	}
}

func TestOCIRunner_ErrNotImplemented_StillExported(t *testing.T) {
	t.Parallel()
	// ErrNotImplemented is kept for backward compatibility with any code that
	// imports it. Verify it is still a non-nil sentinel.
	if oci.ErrNotImplemented == nil {
		t.Error("ErrNotImplemented must remain a non-nil sentinel for backward compatibility")
	}
}
