package oci_test

import (
	"context"
	"errors"
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/runtime/oci"
)

func TestOCIRunner_ReturnsNotImplemented(t *testing.T) {
	t.Parallel()
	r := &oci.OCIRunner{
		ImageDigest: "sha256:abc123",
		Network:     "none",
	}
	_, err := r.Run(context.Background(), ir.CheckerIdentity{ID: "test"}, nil)
	if err == nil {
		t.Fatal("expected ErrNotImplemented, got nil")
	}
	if !errors.Is(err, oci.ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got: %v", err)
	}
}

func TestOCIRunner_RuntimeClass(t *testing.T) {
	t.Parallel()
	if oci.RuntimeClass != "isolated-oci" {
		t.Errorf("RuntimeClass must be %q, got %q", "isolated-oci", oci.RuntimeClass)
	}
}
