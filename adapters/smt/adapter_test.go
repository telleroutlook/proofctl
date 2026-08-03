package smt_test

import (
	"testing"

	"github.com/telleroutlook/proofctl/adapters/smt"
)

func baseSpec(id string, format smt.Format) smt.ProblemSpec {
	return smt.ProblemSpec{
		ProblemID:   id,
		Description: "test",
		Format:      format,
		SMT2Digest:  "sha256:" + "aa" + repeat("0", 62),
		SMT2Size:    100,
		ProofDigest: "sha256:" + "bb" + repeat("0", 62),
		ProofSize:   200,
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func TestCompile_Alethe(t *testing.T) {
	t.Parallel()
	a := &smt.SMTAdapter{}
	pg, err := a.Compile(baseSpec("test-prob", smt.FormatAlethe))
	if err != nil {
		t.Fatalf("Compile(alethe): %v", err)
	}
	if len(pg.Claims) != 3 {
		t.Fatalf("expected 3 claims, got %d", len(pg.Claims))
	}
	wantIDs := []string{"def-test-prob-formula", "lem-test-prob-unsat", "thm-test-prob-verified"}
	for i, want := range wantIDs {
		if pg.Claims[i].ID != want {
			t.Errorf("claims[%d].ID = %q, want %q", i, pg.Claims[i].ID, want)
		}
	}
}

func TestCompile_DRAT(t *testing.T) {
	t.Parallel()
	a := &smt.SMTAdapter{}
	pg, err := a.Compile(baseSpec("sat-prob", smt.FormatDRAT))
	if err != nil {
		t.Fatalf("Compile(drat): %v", err)
	}
	if len(pg.Checkers) != 1 {
		t.Fatalf("expected 1 checker, got %d", len(pg.Checkers))
	}
	// Checker cmd should contain "--format drat".
	found := false
	for _, part := range pg.Checkers[0].Runtime.Cmd {
		if part == "drat" {
			found = true
		}
	}
	if !found {
		t.Errorf("checker cmd should contain 'drat', got %v", pg.Checkers[0].Runtime.Cmd)
	}
}

func TestCompile_EmptyID(t *testing.T) {
	t.Parallel()
	a := &smt.SMTAdapter{}
	_, err := a.Compile(smt.ProblemSpec{Format: smt.FormatAlethe})
	if err == nil {
		t.Error("expected error for empty problem ID, got nil")
	}
}

func TestCompile_InvalidFormat(t *testing.T) {
	t.Parallel()
	a := &smt.SMTAdapter{}
	spec := baseSpec("p", "unsupported")
	_, err := a.Compile(spec)
	if err == nil {
		t.Error("expected error for unsupported format, got nil")
	}
}

func TestCompile_InvalidID(t *testing.T) {
	t.Parallel()
	a := &smt.SMTAdapter{}
	spec := baseSpec("bad/id", smt.FormatAlethe)
	_, err := a.Compile(spec)
	if err == nil {
		t.Error("expected error for problem ID with slash, got nil")
	}
}

func TestCompile_EvidenceCount(t *testing.T) {
	t.Parallel()
	a := &smt.SMTAdapter{}
	pg, err := a.Compile(baseSpec("p1", smt.FormatAlethe))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Evidence) != 2 {
		t.Errorf("expected 2 evidence entries (smt2 + proof), got %d", len(pg.Evidence))
	}
}

func TestCompile_DependencyChain(t *testing.T) {
	t.Parallel()
	a := &smt.SMTAdapter{}
	pg, err := a.Compile(baseSpec("chain", smt.FormatAlethe))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// thm depends on both formula and unsat.
	thm := pg.Claims[2]
	deps := map[string]bool{}
	for _, d := range thm.DependsOn {
		deps[d] = true
	}
	if !deps["def-chain-formula"] || !deps["lem-chain-unsat"] {
		t.Errorf("thm-chain-verified should depend on both def and lem, got %v", thm.DependsOn)
	}
}
