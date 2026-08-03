package coq_test

import (
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/adapters/coq"
)

func TestCompile_EmptySource(t *testing.T) {
	t.Parallel()
	a := &coq.CoqAdapter{}
	_, err := a.Compile(nil)
	if err == nil {
		t.Error("expected error for nil source")
	}
	_, err = a.Compile([]byte{})
	if err == nil {
		t.Error("expected error for empty source")
	}
}

func TestCompile_NoAnnotations(t *testing.T) {
	t.Parallel()
	a := &coq.CoqAdapter{}
	_, err := a.Compile([]byte("Theorem foo : True. Proof. trivial. Qed."))
	if err == nil {
		t.Error("expected error when no (* claim: *) annotations found")
	}
}

func TestCompile_SingleClaim(t *testing.T) {
	t.Parallel()
	a := &coq.CoqAdapter{}
	src := []byte(`
(* claim: thm-CoqProof-foo *)
Theorem foo : True. Proof. trivial. Qed.
`)
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(pg.Claims))
	}
	if pg.Claims[0].ID != "thm-CoqProof-foo" {
		t.Errorf("claim ID: got %q, want thm-CoqProof-foo", pg.Claims[0].ID)
	}
	if pg.Claims[0].BatchGroup != "coq-env" {
		t.Errorf("BatchGroup: got %q, want coq-env", pg.Claims[0].BatchGroup)
	}
}

func TestCompile_MultipleClaims(t *testing.T) {
	t.Parallel()
	a := &coq.CoqAdapter{}
	src := []byte(`
(* claim: thm-CoqProof-lem1 *)
Lemma lem1 : True. Proof. trivial. Qed.
(* claim: thm-CoqProof-main *)
Theorem main : True. Proof. trivial. Qed.
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
	a := &coq.CoqAdapter{}
	src := []byte(`
(* claim: thm-dup *)
(* claim: thm-dup *)
Theorem dup : True. Proof. trivial. Qed.
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
	a := &coq.CoqAdapter{}
	src := []byte("(* claim: thm-a *)\n(* claim: thm-b *)\n")
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for _, c := range pg.Claims {
		if c.BatchGroup != "coq-env" {
			t.Errorf("claim %q BatchGroup = %q, want coq-env", c.ID, c.BatchGroup)
		}
	}
}

func TestCompile_CheckerCmdContainsBridge(t *testing.T) {
	t.Parallel()
	a := &coq.CoqAdapter{}
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
