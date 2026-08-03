package lean_test

import (
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/adapters/lean"
)

func TestCompile_EmptySource(t *testing.T) {
	t.Parallel()
	a := &lean.LeanAdapter{}
	_, err := a.Compile(nil)
	if err == nil {
		t.Error("Compile(nil): expected error for empty source, got nil")
	}
	_, err = a.Compile([]byte{})
	if err == nil {
		t.Error("Compile([]byte{}): expected error for empty source, got nil")
	}
}

func TestCompile_NoAnnotations(t *testing.T) {
	t.Parallel()
	a := &lean.LeanAdapter{}
	_, err := a.Compile([]byte(`-- just a comment
theorem foo : True := trivial`))
	if err == nil {
		t.Error("expected error when no claim annotations, got nil")
	}
}

func TestCompile_SingleClaim(t *testing.T) {
	t.Parallel()
	a := &lean.LeanAdapter{}
	src := []byte(`
-- claim: thm-MyProof-foo
theorem foo : True := trivial
`)
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(pg.Claims))
	}
	if pg.Claims[0].ID != "thm-MyProof-foo" {
		t.Errorf("claim ID: got %q, want %q", pg.Claims[0].ID, "thm-MyProof-foo")
	}
	if pg.Claims[0].BatchGroup != "lean-env" {
		t.Errorf("BatchGroup: got %q, want %q", pg.Claims[0].BatchGroup, "lean-env")
	}
	if pg.Claims[0].CheckerPolicy != "lean-checker-v1" {
		t.Errorf("CheckerPolicy: got %q, want lean-checker-v1", pg.Claims[0].CheckerPolicy)
	}
}

func TestCompile_MultipleClaims(t *testing.T) {
	t.Parallel()
	a := &lean.LeanAdapter{}
	src := []byte(`
-- claim: thm-MyProof-lem1
theorem lem1 : True := trivial

-- claim: thm-MyProof-main
theorem main : True := trivial
`)
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 2 {
		t.Fatalf("expected 2 claims, got %d", len(pg.Claims))
	}
	ids := map[string]bool{}
	for _, c := range pg.Claims {
		ids[c.ID] = true
	}
	for _, want := range []string{"thm-MyProof-lem1", "thm-MyProof-main"} {
		if !ids[want] {
			t.Errorf("missing claim ID %q", want)
		}
	}
}

func TestCompile_DuplicateAnnotation(t *testing.T) {
	t.Parallel()
	a := &lean.LeanAdapter{}
	src := []byte(`
-- claim: thm-dup
-- claim: thm-dup
theorem dup : True := trivial
`)
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Errorf("duplicate annotation should produce 1 claim, got %d", len(pg.Claims))
	}
}

func TestCompile_AllBatchGroup(t *testing.T) {
	t.Parallel()
	a := &lean.LeanAdapter{}
	src := []byte(`
-- claim: thm-a
-- claim: thm-b
-- claim: thm-c
`)
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for _, c := range pg.Claims {
		if c.BatchGroup != "lean-env" {
			t.Errorf("claim %q BatchGroup = %q, want lean-env", c.ID, c.BatchGroup)
		}
	}
}

func TestCompile_CheckerCmdContainsBridge(t *testing.T) {
	t.Parallel()
	a := &lean.LeanAdapter{}
	src := []byte("-- claim: thm-x\n")
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Checkers) == 0 {
		t.Fatal("expected at least one checker")
	}
	cmd := strings.Join(pg.Checkers[0].Runtime.Cmd, " ")
	if !strings.Contains(cmd, "bridge.py") {
		t.Errorf("checker cmd should reference bridge.py, got: %q", cmd)
	}
}
