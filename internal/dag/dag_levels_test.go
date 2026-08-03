package dag_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// addClaim is a test helper that calls AddClaim and fatals on error.
func addClaim(t *testing.T, d *dag.DAG, id string, deps ...string) {
	t.Helper()
	if err := d.AddClaim(&ir.Claim{ID: id, Kind: "lemma", DependsOn: deps}); err != nil {
		t.Fatalf("AddClaim(%q): %v", id, err)
	}
}

// TestLevels_Empty verifies that an empty DAG returns no levels.
func TestLevels_Empty(t *testing.T) {
	t.Parallel()
	d := dag.New()
	if got := d.Levels(); len(got) != 0 {
		t.Errorf("Levels() on empty DAG: want [], got %v", got)
	}
}

// TestLevels_SingleClaim verifies that a single root claim is in level 0.
func TestLevels_SingleClaim(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "root")
	levels := d.Levels()
	if len(levels) != 1 {
		t.Fatalf("want 1 level, got %d: %v", len(levels), levels)
	}
	if !reflect.DeepEqual(levels[0], []string{"root"}) {
		t.Errorf("level[0]: got %v, want [root]", levels[0])
	}
}

// TestLevels_LinearChain verifies that a->b->c produces three separate levels.
func TestLevels_LinearChain(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "a")
	addClaim(t, d, "b", "a")
	addClaim(t, d, "c", "b")
	levels := d.Levels()
	if len(levels) != 3 {
		t.Fatalf("want 3 levels for linear chain, got %d: %v", len(levels), levels)
	}
	want := [][]string{{"a"}, {"b"}, {"c"}}
	for i, wl := range want {
		if !reflect.DeepEqual(levels[i], wl) {
			t.Errorf("level[%d]: got %v, want %v", i, levels[i], wl)
		}
	}
}

// TestLevels_ParallelRoots verifies that two independent root claims are in the same level.
func TestLevels_ParallelRoots(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "r1")
	addClaim(t, d, "r2")
	addClaim(t, d, "tip", "r1", "r2")
	levels := d.Levels()
	if len(levels) != 2 {
		t.Fatalf("want 2 levels, got %d: %v", len(levels), levels)
	}
	// r1 and r2 are both in level 0 (sorted).
	l0 := append([]string(nil), levels[0]...)
	sort.Strings(l0)
	want0 := []string{"r1", "r2"}
	if !reflect.DeepEqual(l0, want0) {
		t.Errorf("level[0]: got %v, want %v", l0, want0)
	}
	if !reflect.DeepEqual(levels[1], []string{"tip"}) {
		t.Errorf("level[1]: got %v, want [tip]", levels[1])
	}
}

// TestLevels_DiamondDAG verifies the classic diamond A→B,A→C,B→D,C→D.
func TestLevels_DiamondDAG(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "a")
	addClaim(t, d, "b", "a")
	addClaim(t, d, "c", "a")
	addClaim(t, d, "d", "b", "c")
	levels := d.Levels()
	if len(levels) != 3 {
		t.Fatalf("want 3 levels for diamond, got %d: %v", len(levels), levels)
	}
	if !reflect.DeepEqual(levels[0], []string{"a"}) {
		t.Errorf("level[0]: got %v, want [a]", levels[0])
	}
	// b and c in level 1 (sorted).
	l1 := append([]string(nil), levels[1]...)
	sort.Strings(l1)
	if !reflect.DeepEqual(l1, []string{"b", "c"}) {
		t.Errorf("level[1]: got %v, want [b c]", l1)
	}
	if !reflect.DeepEqual(levels[2], []string{"d"}) {
		t.Errorf("level[2]: got %v, want [d]", levels[2])
	}
}

// TestLevels_IdsAreSorted verifies that IDs within each level are sorted.
func TestLevels_IdsAreSorted(t *testing.T) {
	t.Parallel()
	d := dag.New()
	// Add roots in reverse alphabetical order.
	for _, id := range []string{"z", "m", "a"} {
		addClaim(t, d, id)
	}
	levels := d.Levels()
	if len(levels) != 1 {
		t.Fatalf("want 1 level, got %d", len(levels))
	}
	want := []string{"a", "m", "z"}
	if !reflect.DeepEqual(levels[0], want) {
		t.Errorf("level[0]: got %v, want %v (not sorted)", levels[0], want)
	}
}

// TestLevels_AllClaimsCovered verifies every claim appears in exactly one level.
func TestLevels_AllClaimsCovered(t *testing.T) {
	t.Parallel()
	d := dag.New()
	ids := []string{"a", "b", "c", "d", "e"}
	addClaim(t, d, "a")
	addClaim(t, d, "b", "a")
	addClaim(t, d, "c", "a")
	addClaim(t, d, "d", "b", "c")
	addClaim(t, d, "e", "d")

	seen := map[string]int{}
	for _, level := range d.Levels() {
		for _, id := range level {
			seen[id]++
		}
	}
	for _, id := range ids {
		if seen[id] != 1 {
			t.Errorf("claim %q appears %d times across levels, want 1", id, seen[id])
		}
	}
}
