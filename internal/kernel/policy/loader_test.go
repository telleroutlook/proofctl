package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/telleroutlook/proofctl/internal/kernel/policy"
)

func TestLoadPolicyV2_Valid(t *testing.T) {
	dir := t.TempDir()
	content := `{"version":"2","target":"thm-main","allowed_assurances":["formal-kernel"]}`
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := policy.LoadPolicyV2(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Target != "thm-main" {
		t.Errorf("target: got %q, want %q", p.Target, "thm-main")
	}
}

func TestLoadPolicyV2_UnknownField(t *testing.T) {
	dir := t.TempDir()
	content := `{"version":"2","target":"thm-main","unknown_field":"bad"}`
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadPolicyV2(path)
	if err == nil {
		t.Error("expected error for unknown field, got nil")
	}
}

func TestLoadPolicyV2_WrongVersion(t *testing.T) {
	dir := t.TempDir()
	content := `{"version":"1","target":"thm-main"}`
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadPolicyV2(path)
	if err == nil {
		t.Error("expected error for version 1, got nil")
	}
}

func TestLoadPolicyV2_MissingTarget(t *testing.T) {
	dir := t.TempDir()
	content := `{"version":"2","allowed_assurances":["formal-kernel"]}`
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadPolicyV2(path)
	if err == nil {
		t.Error("expected error for missing target, got nil")
	}
}
