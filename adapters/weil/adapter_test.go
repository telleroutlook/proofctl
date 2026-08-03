package weil_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/adapters/weil"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// graphPath resolves the path to examples/weil/graph.json relative to the repo root.
func graphPath(t *testing.T) string {
	t.Helper()
	// Walk up from this test file location to find examples/weil/graph.json.
	_, testFile, _, _ := runtime.Caller(0)
	// testFile is adapters/weil/adapter_test.go; repo root is two levels up.
	repoRoot := filepath.Join(filepath.Dir(testFile), "..", "..")
	path := filepath.Join(repoRoot, "examples", "weil", "graph.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("graph.json not found at %s: %v", path, err)
	}
	return path
}

func readGraph(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(graphPath(t))
	if err != nil {
		t.Fatalf("read graph.json: %v", err)
	}
	return data
}

// TestCompile_ValidGraph verifies that compiling with ShadowMode=false returns 12 claims.
func TestCompile_ValidGraph(t *testing.T) {
	t.Parallel()
	a := &weil.Adapter{ShadowMode: false}
	src := readGraph(t)

	graph, atts, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(graph.Claims) != 12 {
		t.Errorf("Claims count = %d, want 12", len(graph.Claims))
	}
	if atts != nil {
		t.Errorf("expected nil attestations in non-shadow mode, got %d entries", len(atts))
	}
}

// TestCompile_ShadowMode verifies that ShadowMode=true produces 12 attestation entries.
func TestCompile_ShadowMode(t *testing.T) {
	t.Parallel()
	a := &weil.Adapter{ShadowMode: true}
	src := readGraph(t)

	graph, atts, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(graph.Claims) != 12 {
		t.Errorf("Claims count = %d, want 12", len(graph.Claims))
	}
	if atts == nil {
		t.Fatal("expected non-nil attestations in shadow mode")
	}
	if len(atts) != 12 {
		t.Errorf("Attestations count = %d, want 12", len(atts))
	}
	// Verify every claim has an attestation entry.
	for _, c := range graph.Claims {
		if _, ok := atts[c.ID]; !ok {
			t.Errorf("missing attestation for claim %q", c.ID)
		}
	}
}

// TestCompile_ShadowMode_D4Blocked verifies that lem-d4-kernel-bound is blocked with D4 reason.
func TestCompile_ShadowMode_D4Blocked(t *testing.T) {
	t.Parallel()
	a := &weil.Adapter{ShadowMode: true}
	src := readGraph(t)

	_, atts, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	att, ok := atts["lem-d4-kernel-bound"]
	if !ok {
		t.Fatal("no attestation for lem-d4-kernel-bound")
	}
	if att.Outcome != string(ir.StatusBlocked) {
		t.Errorf("Outcome = %q, want %q", att.Outcome, ir.StatusBlocked)
	}
	if !strings.Contains(att.BlockReason, "D4") {
		t.Errorf("BlockReason %q does not contain \"D4\"", att.BlockReason)
	}
}

// TestCompile_ShadowMode_D8Blocked verifies that lem-ab-intersection is blocked with D8 reason.
func TestCompile_ShadowMode_D8Blocked(t *testing.T) {
	t.Parallel()
	a := &weil.Adapter{ShadowMode: true}
	src := readGraph(t)

	_, atts, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	att, ok := atts["lem-ab-intersection"]
	if !ok {
		t.Fatal("no attestation for lem-ab-intersection")
	}
	if att.Outcome != string(ir.StatusBlocked) {
		t.Errorf("Outcome = %q, want %q", att.Outcome, ir.StatusBlocked)
	}
	if !strings.Contains(att.BlockReason, "D8") {
		t.Errorf("BlockReason %q does not contain \"D8\"", att.BlockReason)
	}
}

// TestCompile_ShadowMode_D18Blocked verifies that thm-main-radius-030 is blocked.
func TestCompile_ShadowMode_D18Blocked(t *testing.T) {
	t.Parallel()
	a := &weil.Adapter{ShadowMode: true}
	src := readGraph(t)

	_, atts, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	att, ok := atts["thm-main-radius-030"]
	if !ok {
		t.Fatal("no attestation for thm-main-radius-030")
	}
	if att.Outcome != string(ir.StatusBlocked) {
		t.Errorf("Outcome = %q, want %q", att.Outcome, ir.StatusBlocked)
	}
}

// TestCompile_EmptySource verifies that an empty JSON object returns an error.
func TestCompile_EmptySource(t *testing.T) {
	t.Parallel()
	a := &weil.Adapter{ShadowMode: false}

	_, _, err := a.Compile([]byte(`{}`))
	if err == nil {
		t.Error("expected error for empty source, got nil")
	}
}
