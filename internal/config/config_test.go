package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInit_CreatesDirectoryStructure(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := Init(root); err != nil {
		t.Fatalf("Init: %v", err)
	}
	for _, dir := range []string{DirName, filepath.Join(DirName, CASDir), filepath.Join(DirName, AttestDir)} {
		if _, err := os.Stat(filepath.Join(root, dir)); err != nil {
			t.Errorf("expected directory %q to exist: %v", dir, err)
		}
	}
	cfgPath := filepath.Join(root, DirName, ConfigFile)
	if _, err := os.Stat(cfgPath); err != nil {
		t.Errorf("expected config file %q to exist: %v", cfgPath, err)
	}
}

func TestInit_AlreadyExists(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := Init(root); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	if err := Init(root); err == nil {
		t.Fatal("expected error on second Init, got nil")
	}
}

func TestLoad_RoundTrip(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := Init(root); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version != "1" {
		t.Errorf("Version: got %q want %q", cfg.Version, "1")
	}
	if cfg.PolicyFile == "" {
		t.Error("PolicyFile should not be empty after Init")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	_, err := Load(root)
	if err == nil {
		t.Fatal("expected error for missing config file, got nil")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := Init(root); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfgPath := filepath.Join(root, DirName, ConfigFile)
	if err := os.WriteFile(cfgPath, []byte("{bad json}"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := Load(root)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestLoad_UnknownField(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := Init(root); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfgPath := filepath.Join(root, DirName, ConfigFile)
	if err := os.WriteFile(cfgPath, []byte(`{"version":"1","unknown_field":"bad"}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := Load(root)
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}

func TestFind_FindsProjectRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := Init(root); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Find from the project root itself.
	found, err := Find(root)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if found != root {
		t.Errorf("Find: got %q want %q", found, root)
	}
}

func TestFind_FindsFromSubdir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := Init(root); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Create a subdirectory and find from it.
	sub := filepath.Join(root, "subdir", "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	found, err := Find(sub)
	if err != nil {
		t.Fatalf("Find from subdir: %v", err)
	}
	if found != root {
		t.Errorf("Find: got %q want %q", found, root)
	}
}

func TestFind_NoProjectDir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	_, err := Find(root)
	if err == nil {
		t.Fatal("expected error when no .proofctl found, got nil")
	}
	if !strings.Contains(err.Error(), ".proofctl") {
		t.Errorf("error should mention .proofctl, got: %v", err)
	}
}
