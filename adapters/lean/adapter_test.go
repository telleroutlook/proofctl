package lean_test

import (
	"testing"

	"github.com/telleroutlook/proofctl/adapters/lean"
)

// TestCompile_EmptySource verifies that an empty source returns an error.
func TestCompile_EmptySource(t *testing.T) {
	t.Parallel()
	a := &lean.LeanAdapter{Version: "4"}
	_, err := a.Compile(nil)
	if err == nil {
		t.Error("Compile(nil): expected error for empty source, got nil")
	}
	_, err = a.Compile([]byte{})
	if err == nil {
		t.Error("Compile([]byte{}): expected error for empty source, got nil")
	}
}

// TestCompile_NotImplemented verifies that a non-empty source returns the
// "not yet implemented" error (stub behaviour documented in adapter.go).
func TestCompile_NotImplemented(t *testing.T) {
	t.Parallel()
	a := &lean.LeanAdapter{Version: "4"}
	_, err := a.Compile([]byte(`-- some lean source`))
	if err == nil {
		t.Fatal("Compile: expected error from stub, got nil")
	}
}
