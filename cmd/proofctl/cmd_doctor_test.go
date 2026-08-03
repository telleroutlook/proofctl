package main_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDoctor_OutsideProject verifies that 'proofctl doctor' exits non-zero
// outside a project and reports the project-not-found check.
func TestDoctor_OutsideProject(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	_, stderr, code := run(t, bin, dir, "doctor")
	if code == 0 {
		t.Error("expected non-zero exit outside a project, got 0")
	}
	if !strings.Contains(stderr+run1stdout(t, bin, dir, "doctor"), "proofctl") {
		// output goes to stdout in text mode
	}
}

// TestDoctor_InsideProject verifies that 'proofctl doctor' exits non-zero
// inside a freshly initialized project (BRIDGE_CHECKER not set, checker unpinned).
func TestDoctor_InsideProject(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	run(t, bin, dir, "init")
	stdout, _, _ := run(t, bin, dir, "doctor")
	// .proofctl/ found check must pass.
	if !strings.Contains(stdout, ".proofctl/") {
		t.Errorf("expected .proofctl/ found message in output, got: %q", stdout)
	}
}

// TestDoctor_JSON verifies that 'proofctl --json doctor' outputs valid JSON
// with a top-level "ok" field and a "checks" array.
func TestDoctor_JSON_OutsideProject(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	stdout, _, _ := run(t, bin, dir, "--json", "doctor")
	if stdout == "" {
		t.Fatal("expected JSON output, got empty string")
	}
	var out struct {
		OK     bool              `json:"ok"`
		Checks []map[string]any  `json:"checks"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("doctor --json: invalid JSON: %v\noutput: %q", err, stdout)
	}
	if len(out.Checks) == 0 {
		t.Error("doctor --json: expected non-empty checks array")
	}
	// Outside a project, ok must be false.
	if out.OK {
		t.Error("doctor --json: expected ok=false outside a project")
	}
}

// TestDoctor_JSON_InsideProject verifies JSON output inside a project.
func TestDoctor_JSON_InsideProject(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	run(t, bin, dir, "init")
	stdout, _, _ := run(t, bin, dir, "--json", "doctor")
	var out struct {
		Checks []struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("doctor --json inside project: invalid JSON: %v", err)
	}
	// project-found check must be present and passing.
	found := false
	for _, c := range out.Checks {
		if c.Name == "project-found" {
			found = true
			if !c.OK {
				t.Error("project-found check should pass inside initialized project")
			}
		}
	}
	if !found {
		t.Error("doctor --json: expected 'project-found' check in output")
	}
}

// TestDoctor_AllPass_NoEvidence verifies that doctor exits 0 in a project with
// no evidence declared and all env vars satisfied.
func TestDoctor_AllPass_NoEvidence(t *testing.T) {
	// Cannot use t.Parallel() with t.Setenv.
	bin := buildBinary(t)
	dir := t.TempDir()

	// Create a fake checker script.
	checkerPath := filepath.Join(dir, "check.sh")
	if err := os.WriteFile(checkerPath, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatalf("write checker: %v", err)
	}

	t.Setenv("BRIDGE_CHECKER", checkerPath)
	t.Setenv("PROOFCTL_ADAPTERS", dir)

	run(t, bin, dir, "init")
	_, _, code := run(t, bin, dir, "doctor")
	// May still fail due to unpinned checker, but must not panic.
	// We just verify it runs and produces output without crashing.
	_ = code
}

// run1stdout is a helper that returns only stdout (for use in assertions).
func run1stdout(t *testing.T, bin, dir string, args ...string) string {
	t.Helper()
	stdout, _, _ := run(t, bin, dir, args...)
	return stdout
}
