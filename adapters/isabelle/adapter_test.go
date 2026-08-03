package isabelle_test

import (
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/adapters/isabelle"
)

func TestCompile_EmptySource(t *testing.T) {
	t.Parallel()
	a := &isabelle.IsabelleAdapter{}
	_, err := a.Compile(nil)
	if err == nil {
		t.Error("expected error for nil source")
	}
}

func TestCompile_NoAnnotations(t *testing.T) {
	t.Parallel()
	a := &isabelle.IsabelleAdapter{}
	_, err := a.Compile([]byte("theory Foo imports Main begin\nlemma foo: \"True\" by simp\nend"))
	if err == nil {
		t.Error("expected error when no claim annotations found")
	}
}

func TestCompile_BlockCommentAnnotation(t *testing.T) {
	t.Parallel()
	a := &isabelle.IsabelleAdapter{}
	src := []byte(`
theory Foo imports Main begin
(* claim: thm-Foo-foo *)
lemma foo: "True" by simp
end
`)
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(pg.Claims))
	}
	if pg.Claims[0].ID != "thm-Foo-foo" {
		t.Errorf("claim ID: got %q, want thm-Foo-foo", pg.Claims[0].ID)
	}
	if pg.Claims[0].BatchGroup != "isabelle-env" {
		t.Errorf("BatchGroup: got %q, want isabelle-env", pg.Claims[0].BatchGroup)
	}
}

func TestCompile_LineCommentAnnotation(t *testing.T) {
	t.Parallel()
	a := &isabelle.IsabelleAdapter{}
	src := []byte(`
-- claim: thm-Foo-bar
lemma bar: "True" by simp
`)
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 1 || pg.Claims[0].ID != "thm-Foo-bar" {
		t.Errorf("expected thm-Foo-bar, got %v", pg.Claims)
	}
}

func TestCompile_BothAnnotationStyles(t *testing.T) {
	t.Parallel()
	a := &isabelle.IsabelleAdapter{}
	src := []byte(`
(* claim: thm-block *)
-- claim: thm-line
`)
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 2 {
		t.Fatalf("expected 2 claims, got %d", len(pg.Claims))
	}
}

func TestCompile_DuplicateAnnotation(t *testing.T) {
	t.Parallel()
	a := &isabelle.IsabelleAdapter{}
	src := []byte("(* claim: thm-dup *)\n(* claim: thm-dup *)\n")
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Errorf("duplicate should produce 1 claim, got %d", len(pg.Claims))
	}
}

func TestCompile_BatchGroup(t *testing.T) {
	t.Parallel()
	a := &isabelle.IsabelleAdapter{}
	src := []byte("(* claim: thm-a *)\n(* claim: thm-b *)\n")
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for _, c := range pg.Claims {
		if c.BatchGroup != "isabelle-env" {
			t.Errorf("claim %q BatchGroup = %q, want isabelle-env", c.ID, c.BatchGroup)
		}
	}
}

func TestCompile_CheckerCmd(t *testing.T) {
	t.Parallel()
	a := &isabelle.IsabelleAdapter{}
	src := []byte("(* claim: thm-x *)\n")
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cmd := strings.Join(pg.Checkers[0].Runtime.Cmd, " ")
	if !strings.Contains(cmd, "bridge.py") {
		t.Errorf("checker cmd should reference bridge.py, got: %q", cmd)
	}
}
