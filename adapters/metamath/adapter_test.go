package metamath_test

import (
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/adapters/metamath"
)

func TestCompileGraph_EmptySource(t *testing.T) {
	t.Parallel()
	a := &metamath.MetamathAdapter{}
	_, err := a.CompileGraph(nil)
	if err == nil {
		t.Error("expected error for nil source, got nil")
	}
	_, err = a.CompileGraph([]byte{})
	if err == nil {
		t.Error("expected error for empty source, got nil")
	}
}

func TestCompileGraph_NoTheorems(t *testing.T) {
	t.Parallel()
	a := &metamath.MetamathAdapter{}
	src := []byte("$( comment only, no theorems $)")
	_, err := a.CompileGraph(src)
	if err == nil {
		t.Error("expected error when no $p statements found, got nil")
	}
}

func TestCompileGraph_SingleTheorem(t *testing.T) {
	t.Parallel()
	a := &metamath.MetamathAdapter{}
	src := []byte(`
$c |- $.
$v ph $.
wph $f wff ph $.
thm-mp $p |- ph $= wph $.
`)
	pg, err := a.CompileGraph(src)
	if err != nil {
		t.Fatalf("CompileGraph: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(pg.Claims))
	}
	if pg.Claims[0].ID != "thm-thm-mp" {
		t.Errorf("claim ID: got %q, want %q", pg.Claims[0].ID, "thm-thm-mp")
	}
	if pg.Claims[0].Kind != "theorem" {
		t.Errorf("claim kind: got %q, want theorem", pg.Claims[0].Kind)
	}
}

func TestCompileGraph_MultipleTheorems(t *testing.T) {
	t.Parallel()
	a := &metamath.MetamathAdapter{}
	src := []byte(`
$c |- $.
$v ph ps $.
wph $f wff ph $.
wps $f wff ps $.
thm-ax1 $p |- ph $= wph $.
thm-ax2 $p |- ps $= wps $.
`)
	pg, err := a.CompileGraph(src)
	if err != nil {
		t.Fatalf("CompileGraph: %v", err)
	}
	if len(pg.Claims) != 2 {
		t.Fatalf("expected 2 claims, got %d", len(pg.Claims))
	}
	ids := map[string]bool{}
	for _, c := range pg.Claims {
		ids[c.ID] = true
	}
	for _, want := range []string{"thm-thm-ax1", "thm-thm-ax2"} {
		if !ids[want] {
			t.Errorf("missing claim ID %q in output", want)
		}
	}
}

func TestCompileGraph_DuplicateLabel(t *testing.T) {
	t.Parallel()
	a := &metamath.MetamathAdapter{}
	src := []byte(`
thm-dup $p |- ph $= wph $.
thm-dup $p |- ph $= wph $.
`)
	pg, err := a.CompileGraph(src)
	if err != nil {
		t.Fatalf("CompileGraph: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Errorf("duplicate label should produce 1 claim, got %d", len(pg.Claims))
	}
}

func TestCompileGraph_CheckerPopulated(t *testing.T) {
	t.Parallel()
	a := &metamath.MetamathAdapter{}
	src := []byte("thm-x $p |- ph $= wph $.")
	pg, err := a.CompileGraph(src)
	if err != nil {
		t.Fatalf("CompileGraph: %v", err)
	}
	if len(pg.Checkers) == 0 {
		t.Fatal("expected at least one checker entry")
	}
	if pg.Checkers[0].ID != "metamath-checker-v1" {
		t.Errorf("checker ID: got %q, want metamath-checker-v1", pg.Checkers[0].ID)
	}
	if len(pg.Checkers[0].Runtime.Cmd) == 0 {
		t.Error("checker Runtime.Cmd should not be empty")
	}
}

func TestCompileGraph_LabelSanitization(t *testing.T) {
	t.Parallel()
	a := &metamath.MetamathAdapter{}
	// Label with special chars that need sanitization.
	src := []byte("ax*1 $p |- ph $= wph $.")
	pg, err := a.CompileGraph(src)
	if err != nil {
		t.Fatalf("CompileGraph: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(pg.Claims))
	}
	id := pg.Claims[0].ID
	if strings.ContainsAny(id, "*=") {
		t.Errorf("claim ID %q contains invalid characters after sanitization", id)
	}
}
