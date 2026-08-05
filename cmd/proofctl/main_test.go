package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildBinary compiles the proofctl binary to a temp directory and returns its path.
// The binary is reused across all tests in a single run via t.TempDir().
func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "proofctl")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build proofctl: %v\n%s", err, out)
	}
	return bin
}

// run executes the binary with the given args in dir, returning stdout, stderr, and exit code.
func run(t *testing.T, bin, dir string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	}
	return outBuf.String(), errBuf.String(), code
}

// TestHelp verifies that proofctl with no args exits non-zero and prints usage.
func TestHelp(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	_, stderr, code := run(t, bin, dir)
	if code == 0 {
		t.Error("expected non-zero exit code with no subcommand")
	}
	if !strings.Contains(stderr, "proofctl") {
		t.Errorf("expected usage output to contain 'proofctl', got: %q", stderr)
	}
}

// TestHelp_ContainsAllSubcommands verifies that the usage output lists all 17 subcommands.
func TestHelp_ContainsAllSubcommands(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	_, stderr, _ := run(t, bin, dir)
	for _, sub := range []string{
		"init", "domains", "compile", "check", "verify", "explain",
		"graph", "frontier", "impact", "cache", "cas", "pin",
		"env", "replay", "release", "snapshot", "status",
	} {
		if !strings.Contains(stderr, sub) {
			t.Errorf("usage output missing subcommand %q", sub)
		}
	}
}

// TestUnknownSubcommand verifies that an unknown subcommand exits non-zero.
func TestUnknownSubcommand(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	_, _, code := run(t, bin, dir, "no-such-cmd")
	if code == 0 {
		t.Error("expected non-zero exit for unknown subcommand")
	}
}

// TestInit_NoArgs verifies that 'proofctl init' (no domain) creates .proofctl/.
func TestInit_NoArgs(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	_, _, code := run(t, bin, dir, "init")
	if code != 0 {
		t.Errorf("proofctl init: expected exit 0, got %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, ".proofctl")); os.IsNotExist(err) {
		t.Error(".proofctl/ directory not created by 'proofctl init'")
	}
}

// TestInit_UnknownDomain verifies that --domain with an unknown name exits non-zero.
func TestInit_UnknownDomain(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	_, _, code := run(t, bin, dir, "init", "--domain", "no-such-domain")
	if code == 0 {
		t.Error("expected non-zero exit for unknown domain")
	}
}

// TestInit_JSON verifies that 'proofctl init --json' exits 0 (JSON mode doesn't change init).
func TestInit_JSON(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	_, _, code := run(t, bin, dir, "--json", "init")
	if code != 0 {
		t.Errorf("proofctl --json init: expected exit 0, got %d", code)
	}
}

// TestDomainsListText verifies that 'proofctl domains list' prints known domains.
func TestDomainsListText(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	stdout, _, code := run(t, bin, dir, "domains", "list")
	if code != 0 {
		t.Errorf("proofctl domains list: expected exit 0, got %d", code)
	}
	for _, domain := range []string{"cap", "lrat", "qmd"} {
		if !strings.Contains(stdout, domain) {
			t.Errorf("domains list output missing %q", domain)
		}
	}
}

// TestDomainsListJSON verifies that 'proofctl domains list --json' outputs valid JSON.
func TestDomainsListJSON(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	stdout, _, code := run(t, bin, dir, "--json", "domains", "list")
	if code != 0 {
		t.Errorf("proofctl --json domains list: expected exit 0, got %d", code)
	}
	var out any
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Errorf("domains list --json: invalid JSON: %v\noutput: %q", err, stdout)
	}
}

// TestStatusNoGraph verifies that 'proofctl status' outside a project is handled gracefully.
func TestStatusNoGraph(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	// No .proofctl/ initialized — should exit non-zero with an error message.
	_, stderr, code := run(t, bin, dir, "status")
	if code == 0 {
		t.Error("expected non-zero exit for 'status' outside a project")
	}
	if stderr == "" {
		t.Error("expected error output for 'status' outside a project")
	}
}

// TestStatusJSON_NoGraph verifies that --json flag produces JSON error output.
func TestStatusJSON_NoGraph(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	_, stderr, code := run(t, bin, dir, "--json", "status")
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	// stderr should contain JSON-shaped error.
	if !strings.Contains(stderr, "{") {
		t.Errorf("expected JSON error output, got: %q", stderr)
	}
}

// TestCompile_MissingArg verifies that 'proofctl compile' with no graph file exits non-zero.
func TestCompile_MissingArg(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	// init first so we are inside a project
	run(t, bin, dir, "init")
	_, _, code := run(t, bin, dir, "compile")
	if code == 0 {
		t.Error("proofctl compile with no args: expected non-zero exit")
	}
}

// TestInit_DomainCap verifies that 'proofctl init --domain cap' writes scaffold files.
func TestInit_DomainCap(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	_, _, code := run(t, bin, dir, "init", "--domain", "cap")
	if code != 0 {
		t.Errorf("init --domain cap: expected exit 0, got %d", code)
	}
	for _, rel := range []string{
		"graph.json",
		filepath.Join("policies", "cap-v1.json"),
		filepath.Join("adapters", "bridge.py"),
	} {
		if _, err := os.Stat(filepath.Join(dir, rel)); os.IsNotExist(err) {
			t.Errorf("init --domain cap: expected file %q not created", rel)
		}
	}
}

// TestVerify_NoProject verifies that 'proofctl verify' outside a project exits non-zero.
func TestVerify_NoProject(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	_, _, code := run(t, bin, dir, "verify", "--claim", "x")
	if code == 0 {
		t.Error("proofctl verify outside project: expected non-zero exit")
	}
}

// TestExplain_NoProject verifies that 'proofctl explain' outside a project exits non-zero.
func TestExplain_NoProject(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	_, _, code := run(t, bin, dir, "explain", "some-claim")
	if code == 0 {
		t.Error("proofctl explain outside project: expected non-zero exit")
	}
}

// TestGraph_NoProject verifies that 'proofctl graph' outside a project is handled gracefully.
func TestGraph_NoProject(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()
	_, _, code := run(t, bin, dir, "graph")
	if code == 0 {
		t.Error("proofctl graph outside project: expected non-zero exit")
	}
}

// writeMinimalGraph writes a graph.json with one checker to dir and
// runs proofctl init + compile --fix-digests so .proofctl/graph.json exists.
func writeMinimalGraph(t *testing.T, bin, dir, _ string) {
	t.Helper()
	zeroDigest := strings.Repeat("0", 64)
	graph := `{
  "claims": [{"id":"c1","kind":"lemma","statement":{"text":"t","digest":"sha256:` + zeroDigest + `"},"depends_on":[],"evidence":[],"checker_policy":"ck1"}],
  "checkers": [{"id":"ck1","protocol_version":1,"checker_digest":"sha256:` + zeroDigest + `","runtime":{"kind":"native"}}],
  "evidence": []
}`
	if err := os.WriteFile(filepath.Join(dir, "graph.json"), []byte(graph), 0o644); err != nil {
		t.Fatalf("write graph.json: %v", err)
	}
	run(t, bin, dir, "init")
	run(t, bin, dir, "compile", "--fix-digests", "graph.json")
}

// TestPinChecker_NoLock verifies that 'proofctl pin checker' without --lock
// prints a warning about unpinned dependencies.
func TestPinChecker_NoLock(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()

	script := filepath.Join(dir, "check.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	writeMinimalGraph(t, bin, dir, script)

	// Use a relative path so the absolute-path guard does not trigger.
	stdout, stderr, _ := run(t, bin, dir, "pin", "checker", "--cmd", "sh check.sh")
	combined := stdout + stderr
	if !strings.Contains(combined, "warn") && !strings.Contains(combined, "not pinned") {
		t.Errorf("expected dependency-not-pinned warning, got stdout=%q stderr=%q", stdout, stderr)
	}
}

// TestPinChecker_WithLock verifies that --lock pins both script and lockfile digests.
func TestPinChecker_WithLock(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	dir := t.TempDir()

	script := filepath.Join(dir, "check.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	lockfile := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(lockfile, []byte("numpy==1.26.0\n"), 0o644); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}
	writeMinimalGraph(t, bin, dir, script)

	// Use relative paths so the absolute-path guard does not trigger.
	_, stderr, code := run(t, bin, dir, "pin", "checker",
		"--cmd", "sh check.sh",
		"--lock", "requirements.txt",
	)
	if code != 0 {
		t.Fatalf("pin checker --lock: expected exit 0, got %d, stderr=%q", code, stderr)
	}
	// The lock warning must not appear; the schema warning is expected (no --schema given).
	if strings.Contains(stderr, "dependencies not pinned") {
		t.Errorf("unexpected lock warning when --lock provided: %q", stderr)
	}

	// The graph source should now contain dependency_manifest_digest.
	data, err := os.ReadFile(filepath.Join(dir, ".proofctl", "graph.json"))
	if err != nil {
		t.Fatalf("read graph.json: %v", err)
	}
	if !strings.Contains(string(data), "dependency_manifest_digest") {
		t.Error("graph.json should contain dependency_manifest_digest after pin --lock")
	}
}
