package lrat_test

import (
	"encoding/json"
	"testing"

	lrat "github.com/telleroutlook/proofctl/adapters/lrat"
	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	lratdomain "github.com/telleroutlook/proofctl/internal/lrat"
)

// validSpec returns a complete, valid ProblemSpec for testing.
func validSpec() lrat.ProblemSpec {
	return lrat.ProblemSpec{
		ProblemID:    "pigeonhole-3",
		Description:  "3-into-2 pigeonhole — UNSAT",
		CNFDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CNFSize:      512,
		LRATDigest:   "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		LRATSize:     2048,
		NumVariables: 6,
		NumClauses:   12,
	}
}

// TestCompile_ValidSpec verifies a valid ProblemSpec produces 3 claims with correct
// IDs, kinds, and dependency structure.
func TestCompile_ValidSpec(t *testing.T) {
	t.Parallel()
	a := &lrat.Adapter{}
	graph, err := a.Compile(validSpec())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(graph.Claims) != 3 {
		t.Fatalf("Claims count = %d, want 3", len(graph.Claims))
	}

	wantIDs := []string{
		"def-pigeonhole-3-formula",
		"lem-pigeonhole-3-unsat",
		"thm-pigeonhole-3-verified",
	}
	wantKinds := []string{
		lratdomain.KindCNFFormula,
		lratdomain.KindUNSATClaim,
		lratdomain.KindLRATVerified,
	}
	for i, c := range graph.Claims {
		if c.ID != wantIDs[i] {
			t.Errorf("claim[%d].ID = %q, want %q", i, c.ID, wantIDs[i])
		}
		if c.Kind != wantKinds[i] {
			t.Errorf("claim[%d].Kind = %q, want %q", i, c.Kind, wantKinds[i])
		}
	}
}

// TestCompile_EmptyProblemID verifies that an empty problem ID returns an error.
func TestCompile_EmptyProblemID(t *testing.T) {
	t.Parallel()
	a := &lrat.Adapter{}
	spec := validSpec()
	spec.ProblemID = ""
	_, err := a.Compile(spec)
	if err == nil {
		t.Error("expected error for empty problem ID, got nil")
	}
}

// TestCompile_InvalidCharsInID verifies that a problem ID with "/" returns an error.
func TestCompile_InvalidCharsInID(t *testing.T) {
	t.Parallel()
	a := &lrat.Adapter{}

	invalidIDs := []string{"a/b", "a b", "a\\b", "a:b"}
	for _, id := range invalidIDs {
		spec := validSpec()
		spec.ProblemID = id
		_, err := a.Compile(spec)
		if err == nil {
			t.Errorf("expected error for problem ID %q, got nil", id)
		}
	}
}

// TestCompile_ClaimsFormDependencyChain verifies formula <- unsat <- verified
// forms a valid DAG.
func TestCompile_ClaimsFormDependencyChain(t *testing.T) {
	t.Parallel()
	a := &lrat.Adapter{}
	graph, err := a.Compile(validSpec())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	formulaID := graph.Claims[0].ID
	unsatID := graph.Claims[1].ID
	thmID := graph.Claims[2].ID

	// formula has no dependencies.
	if len(graph.Claims[0].DependsOn) != 0 {
		t.Errorf("formula DependsOn = %v, want empty", graph.Claims[0].DependsOn)
	}
	// unsat depends on formula.
	if len(graph.Claims[1].DependsOn) != 1 || graph.Claims[1].DependsOn[0] != formulaID {
		t.Errorf("unsat DependsOn = %v, want [%s]", graph.Claims[1].DependsOn, formulaID)
	}
	// thm depends on formula and unsat.
	if len(graph.Claims[2].DependsOn) != 2 {
		t.Errorf("thm DependsOn count = %d, want 2", len(graph.Claims[2].DependsOn))
	} else {
		found := map[string]bool{formulaID: false, unsatID: false}
		for _, dep := range graph.Claims[2].DependsOn {
			found[dep] = true
		}
		for id, ok := range found {
			if !ok {
				t.Errorf("thm missing dependency on %q", id)
			}
		}
	}
	_ = thmID

	// Verify the DAG validates.
	d := dag.New()
	for i := range graph.Claims {
		if err := d.AddClaim(&graph.Claims[i]); err != nil {
			t.Fatalf("AddClaim %q: %v", graph.Claims[i].ID, err)
		}
	}
	if err := d.Validate(); err != nil {
		t.Errorf("dag.Validate: %v", err)
	}
}

// TestCompile_EvidenceDescriptors verifies 2 evidence descriptors with correct media types.
func TestCompile_EvidenceDescriptors(t *testing.T) {
	t.Parallel()
	a := &lrat.Adapter{}
	spec := validSpec()
	graph, err := a.Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	if len(graph.Evidence) != 2 {
		t.Fatalf("Evidence count = %d, want 2", len(graph.Evidence))
	}

	cnf := graph.Evidence[0]
	lratEv := graph.Evidence[1]

	if cnf.MediaType != lratdomain.CNFMediaType {
		t.Errorf("cnf MediaType = %q, want %q", cnf.MediaType, lratdomain.CNFMediaType)
	}
	if cnf.Digest != spec.CNFDigest {
		t.Errorf("cnf Digest = %q, want %q", cnf.Digest, spec.CNFDigest)
	}
	if cnf.Size != spec.CNFSize {
		t.Errorf("cnf Size = %d, want %d", cnf.Size, spec.CNFSize)
	}

	if lratEv.MediaType != lratdomain.CertificateMediaType {
		t.Errorf("lrat MediaType = %q, want %q", lratEv.MediaType, lratdomain.CertificateMediaType)
	}
	if lratEv.Digest != spec.LRATDigest {
		t.Errorf("lrat Digest = %q, want %q", lratEv.Digest, spec.LRATDigest)
	}
	if lratEv.Size != spec.LRATSize {
		t.Errorf("lrat Size = %d, want %d", lratEv.Size, spec.LRATSize)
	}
}

// TestCompile_StatementDigests verifies each claim's statement digest matches
// ir.StatementDigest(text).
func TestCompile_StatementDigests(t *testing.T) {
	t.Parallel()
	a := &lrat.Adapter{}
	graph, err := a.Compile(validSpec())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	for _, c := range graph.Claims {
		want := ir.StatementDigest(c.Statement.Text)
		if c.Statement.Digest != want {
			t.Errorf("claim %q: statement digest = %q, want %q",
				c.ID, c.Statement.Digest, want)
		}
	}
}

// TestCompile_Deterministic verifies that compiling the same spec twice
// produces identical JSON output.
func TestCompile_Deterministic(t *testing.T) {
	t.Parallel()
	a := &lrat.Adapter{}
	spec := validSpec()

	g1, err := a.Compile(spec)
	if err != nil {
		t.Fatalf("Compile #1: %v", err)
	}
	g2, err := a.Compile(spec)
	if err != nil {
		t.Fatalf("Compile #2: %v", err)
	}

	b1, err := json.Marshal(g1)
	if err != nil {
		t.Fatalf("marshal #1: %v", err)
	}
	b2, err := json.Marshal(g2)
	if err != nil {
		t.Fatalf("marshal #2: %v", err)
	}

	if string(b1) != string(b2) {
		t.Errorf("non-deterministic output:\n  first:  %s\n  second: %s", b1, b2)
	}
}

// TestCompile_CheckerIdentity verifies the checker in the result matches
// lratdomain.LRATCheckerID.
func TestCompile_CheckerIdentity(t *testing.T) {
	t.Parallel()
	a := &lrat.Adapter{}
	graph, err := a.Compile(validSpec())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	if len(graph.Checkers) != 1 {
		t.Fatalf("Checkers count = %d, want 1", len(graph.Checkers))
	}

	ch := graph.Checkers[0]
	want := lratdomain.LRATCheckerID

	if ch.ID != want.ID {
		t.Errorf("Checker.ID = %q, want %q", ch.ID, want.ID)
	}
	if ch.ProtocolVersion != want.ProtocolVersion {
		t.Errorf("Checker.ProtocolVersion = %d, want %d", ch.ProtocolVersion, want.ProtocolVersion)
	}
	if ch.CheckerDigest != want.CheckerDigest {
		t.Errorf("Checker.CheckerDigest = %q, want %q", ch.CheckerDigest, want.CheckerDigest)
	}
	if ch.Runtime.Kind != want.Runtime.Kind {
		t.Errorf("Checker.Runtime.Kind = %q, want %q", ch.Runtime.Kind, want.Runtime.Kind)
	}
	if ch.Network != want.Network {
		t.Errorf("Checker.Network = %q, want %q", ch.Network, want.Network)
	}
}
