package runner

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveCmdPaths_NoExpansion verifies that an absolute path with no
// variables is returned unchanged.
func TestResolveCmdPaths_NoExpansion(t *testing.T) {
	t.Parallel()
	r := &NativeRunner{}
	cmd := []string{"python3", "/absolute/path/bridge.py"}
	got, err := r.resolveCmdPaths(cmd)
	if err != nil {
		t.Fatalf("resolveCmdPaths: unexpected error: %v", err)
	}
	if got[0] != "python3" {
		t.Errorf("cmd[0]: got %q, want %q", got[0], "python3")
	}
	if got[1] != "/absolute/path/bridge.py" {
		t.Errorf("cmd[1]: got %q, want %q", got[1], "/absolute/path/bridge.py")
	}
}

// TestResolveCmdPaths_EnvExpansion verifies that ${VAR} placeholders are expanded.
func TestResolveCmdPaths_EnvExpansion(t *testing.T) {
	// Cannot use t.Parallel() with t.Setenv.
	// Create a real temp file so the stat check passes.
	dir := t.TempDir()
	script := filepath.Join(dir, "bridge.py")
	if err := os.WriteFile(script, []byte("# bridge"), 0o644); err != nil {
		t.Fatalf("write bridge.py: %v", err)
	}

	t.Setenv("TEST_ADAPTERS_DIR", dir)
	r := &NativeRunner{}
	cmd := []string{"python3", "${TEST_ADAPTERS_DIR}/bridge.py"}
	got, err := r.resolveCmdPaths(cmd)
	if err != nil {
		t.Fatalf("resolveCmdPaths: unexpected error: %v", err)
	}
	if got[1] != script {
		t.Errorf("cmd[1]: got %q, want %q", got[1], script)
	}
}

// TestResolveCmdPaths_RelativePathWithRoot verifies that a relative path is
// joined against ProjectRoot and must exist.
func TestResolveCmdPaths_RelativePathWithRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	script := filepath.Join(root, "adapters", "bridge.py")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(script, []byte("# bridge"), 0o644); err != nil {
		t.Fatalf("write bridge.py: %v", err)
	}

	r := &NativeRunner{ProjectRoot: root}
	cmd := []string{"python3", "adapters/bridge.py"}
	got, err := r.resolveCmdPaths(cmd)
	if err != nil {
		t.Fatalf("resolveCmdPaths: unexpected error: %v", err)
	}
	if got[1] != script {
		t.Errorf("cmd[1]: got %q, want %q", got[1], script)
	}
}

// TestResolveCmdPaths_RelativePathMissing verifies that a relative path that
// does not exist returns an error.
func TestResolveCmdPaths_RelativePathMissing(t *testing.T) {
	t.Parallel()
	r := &NativeRunner{ProjectRoot: t.TempDir()}
	cmd := []string{"python3", "adapters/no-such-file.py"}
	_, err := r.resolveCmdPaths(cmd)
	if err == nil {
		t.Error("expected error for missing relative path, got nil")
	}
}

// TestResolveCmdPaths_FlagNotResolved verifies that flags (starting with '-')
// are passed through without path resolution.
func TestResolveCmdPaths_FlagNotResolved(t *testing.T) {
	t.Parallel()
	r := &NativeRunner{ProjectRoot: t.TempDir()}
	cmd := []string{"python3", "--verbose"}
	got, err := r.resolveCmdPaths(cmd)
	if err != nil {
		t.Fatalf("resolveCmdPaths: unexpected error for flag arg: %v", err)
	}
	if got[1] != "--verbose" {
		t.Errorf("cmd[1]: got %q, want %q", got[1], "--verbose")
	}
}

// TestResolveCmdPaths_EmptyArg verifies that an empty string arg is kept as-is.
func TestResolveCmdPaths_EmptyArg(t *testing.T) {
	t.Parallel()
	r := &NativeRunner{ProjectRoot: t.TempDir()}
	cmd := []string{"python3", ""}
	got, err := r.resolveCmdPaths(cmd)
	if err != nil {
		t.Fatalf("resolveCmdPaths: unexpected error for empty arg: %v", err)
	}
	if got[1] != "" {
		t.Errorf("cmd[1]: got %q, want empty", got[1])
	}
}
