package dag

import (
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// claim is a helper to build an ir.Claim for tests.
func claim(t *testing.T, id string, deps ...string) *ir.Claim {
	t.Helper()
	return &ir.Claim{
		ID:        id,
		Kind:      "test",
		DependsOn: deps,
	}
}

// TestAddClaimDuplicate checks that adding a duplicate claim ID returns an error.
func TestAddClaimDuplicate(t *testing.T) {
	t.Parallel()
	d := New()
	if err := d.AddClaim(claim(t, "a")); err != nil {
		t.Fatalf("first add: %v", err)
	}
	err := d.AddClaim(claim(t, "a"))
	if err == nil {
		t.Fatal("expected error for duplicate ID, got nil")
	}
}

// TestValidateEmptyDAG checks that Validate on an empty DAG returns nil.
func TestValidateEmptyDAG(t *testing.T) {
	t.Parallel()
	d := New()
	if err := d.Validate(); err != nil {
		t.Errorf("expected nil for empty DAG, got: %v", err)
	}
}

// TestValidateLinearChain checks that a linear chain A->B->C validates without error.
func TestValidateLinearChain(t *testing.T) {
	t.Parallel()
	d := New()
	// A depends on B, B depends on C.
	mustAdd(t, d, claim(t, "c"))
	mustAdd(t, d, claim(t, "b", "c"))
	mustAdd(t, d, claim(t, "a", "b"))
	if err := d.Validate(); err != nil {
		t.Errorf("expected nil for linear chain, got: %v", err)
	}
}

// TestValidateCycle checks that a cycle A->B->A is detected.
func TestValidateCycle(t *testing.T) {
	t.Parallel()
	d := New()
	mustAdd(t, d, claim(t, "a", "b"))
	mustAdd(t, d, claim(t, "b", "a"))
	err := d.Validate()
	if err == nil {
		t.Fatal("expected cycle error, got nil")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("expected error to contain %q, got: %v", "cycle", err)
	}
}

// TestValidateMissingDependency checks that a missing dependency returns an error.
func TestValidateMissingDependency(t *testing.T) {
	t.Parallel()
	d := New()
	mustAdd(t, d, claim(t, "a", "nonexistent"))
	err := d.Validate()
	if err == nil {
		t.Fatal("expected error for missing dependency, got nil")
	}
}

// TestClosureLeaf checks that Closure on a leaf node (no deps) returns empty.
func TestClosureLeaf(t *testing.T) {
	t.Parallel()
	d := New()
	mustAdd(t, d, claim(t, "leaf"))
	got, err := d.Closure("leaf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty closure for leaf, got: %v", got)
	}
}

// TestClosureChainOfThree checks that Closure on the top of a chain of 3 returns correct set.
func TestClosureChainOfThree(t *testing.T) {
	t.Parallel()
	d := New()
	mustAdd(t, d, claim(t, "c"))
	mustAdd(t, d, claim(t, "b", "c"))
	mustAdd(t, d, claim(t, "a", "b"))

	got, err := d.Closure("a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Closure of "a" should include "b" and "c".
	if len(got) != 2 {
		t.Errorf("expected 2 items in closure, got %d: %v", len(got), got)
	}
	gotSet := toSet(got)
	for _, want := range []string{"b", "c"} {
		if !gotSet[want] {
			t.Errorf("closure missing %q: %v", want, got)
		}
	}
}

// TestClosureDoesNotContainSelf checks the property that Closure(x) never contains x.
func TestClosureDoesNotContainSelf(t *testing.T) {
	t.Parallel()
	d := New()
	mustAdd(t, d, claim(t, "c"))
	mustAdd(t, d, claim(t, "b", "c"))
	mustAdd(t, d, claim(t, "a", "b"))

	for _, id := range []string{"a", "b", "c"} {
		closure, err := d.Closure(id)
		if err != nil {
			t.Fatalf("Closure(%q): %v", id, err)
		}
		for _, dep := range closure {
			if dep == id {
				t.Errorf("Closure(%q) contains itself", id)
			}
		}
	}
}

// TestImpactOnRoot checks that Impact on the root of a chain returns correct set.
func TestImpactOnRoot(t *testing.T) {
	t.Parallel()
	d := New()
	mustAdd(t, d, claim(t, "a"))
	got, err := d.Impact("a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty impact for isolated node, got: %v", got)
	}
}

// TestImpactOnMiddleNode checks that Impact on a middle node returns correct set.
func TestImpactOnMiddleNode(t *testing.T) {
	t.Parallel()
	d := New()
	mustAdd(t, d, claim(t, "c"))
	mustAdd(t, d, claim(t, "b", "c"))
	mustAdd(t, d, claim(t, "a", "b"))

	// Impact of "b": "a" depends on "b", so impact = {"a"}.
	got, err := d.Impact("b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("impact of b: expected [a], got %v", got)
	}
}

// TestImpactOnLeafNode checks that Impact on the deepest leaf returns the full upward set.
func TestImpactOnLeafNode(t *testing.T) {
	t.Parallel()
	d := New()
	mustAdd(t, d, claim(t, "c"))
	mustAdd(t, d, claim(t, "b", "c"))
	mustAdd(t, d, claim(t, "a", "b"))

	// Impact of "c": both "b" and "a" transitively depend on "c".
	got, err := d.Impact("c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gotSet := toSet(got)
	for _, want := range []string{"a", "b"} {
		if !gotSet[want] {
			t.Errorf("impact of c missing %q: got %v", want, got)
		}
	}
}

// TestFrontierDirectDeps checks that Frontier returns the direct dependencies.
func TestFrontierDirectDeps(t *testing.T) {
	t.Parallel()
	d := New()
	mustAdd(t, d, claim(t, "x"))
	mustAdd(t, d, claim(t, "y"))
	mustAdd(t, d, claim(t, "z", "x", "y"))

	got, err := d.Frontier("z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 direct deps, got %d: %v", len(got), got)
	}
	gotSet := toSet(got)
	for _, want := range []string{"x", "y"} {
		if !gotSet[want] {
			t.Errorf("frontier missing %q: %v", want, got)
		}
	}
}

// TestFrontierUnknownClaim checks that Frontier on an unknown claim returns an error.
func TestFrontierUnknownClaim(t *testing.T) {
	t.Parallel()
	d := New()
	_, err := d.Frontier("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown claim, got nil")
	}
}

// TestClaimsPreservesInsertionOrder checks that Claims() returns claims in insertion order.
func TestClaimsPreservesInsertionOrder(t *testing.T) {
	t.Parallel()
	d := New()
	ids := []string{"first", "second", "third", "fourth"}
	for _, id := range ids {
		mustAdd(t, d, claim(t, id))
	}
	claims := d.Claims()
	if len(claims) != len(ids) {
		t.Fatalf("expected %d claims, got %d", len(ids), len(claims))
	}
	for i, c := range claims {
		if c.ID != ids[i] {
			t.Errorf("position %d: got %q want %q", i, c.ID, ids[i])
		}
	}
}

// TestClosureUnknownClaim checks that Closure on an unknown claim returns an error.
func TestClosureUnknownClaim(t *testing.T) {
	t.Parallel()
	d := New()
	_, err := d.Closure("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown claim, got nil")
	}
}

// TestImpactUnknownClaim checks that Impact on an unknown claim returns an error.
func TestImpactUnknownClaim(t *testing.T) {
	t.Parallel()
	d := New()
	_, err := d.Impact("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown claim, got nil")
	}
}

// TestClaimLookup checks that Claim() returns the right claim or nil.
func TestClaimLookup(t *testing.T) {
	t.Parallel()
	d := New()
	mustAdd(t, d, claim(t, "exists"))
	if got := d.Claim("exists"); got == nil {
		t.Error("expected non-nil for existing claim")
	}
	if got := d.Claim("missing"); got != nil {
		t.Errorf("expected nil for missing claim, got %+v", got)
	}
}

// mustAdd is a helper that calls AddClaim and fatals on error.
func mustAdd(t *testing.T, d *DAG, c *ir.Claim) {
	t.Helper()
	if err := d.AddClaim(c); err != nil {
		t.Fatalf("AddClaim(%q): %v", c.ID, err)
	}
}

// toSet converts a string slice to a set for membership testing.
func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}
