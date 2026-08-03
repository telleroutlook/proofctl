package dag_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// TestAdversarial_CycleDetected loads dag_cycle.json, builds a DAG, and checks
// that Validate returns an error containing "cycle".
func TestAdversarial_CycleDetected(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../../testdata/adversarial/dag_cycle.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var pg ir.ProofGraph
	if err := json.Unmarshal(data, &pg); err != nil {
		t.Fatalf("unmarshal ProofGraph: %v", err)
	}

	d := dag.New()
	for i := range pg.Claims {
		if addErr := d.AddClaim(&pg.Claims[i]); addErr != nil {
			t.Fatalf("AddClaim: %v", addErr)
		}
	}

	err = d.Validate()
	if err == nil {
		t.Fatal("expected cycle error, got nil")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("expected error to contain %q, got: %v", "cycle", err)
	}
}

// TestAdversarial_MissingDependency loads dag_missing_dep.json and checks
// that Validate returns an error containing the missing dependency ID.
func TestAdversarial_MissingDependency(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../../testdata/adversarial/dag_missing_dep.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var pg ir.ProofGraph
	if err := json.Unmarshal(data, &pg); err != nil {
		t.Fatalf("unmarshal ProofGraph: %v", err)
	}

	d := dag.New()
	for i := range pg.Claims {
		if addErr := d.AddClaim(&pg.Claims[i]); addErr != nil {
			t.Fatalf("AddClaim: %v", addErr)
		}
	}

	err = d.Validate()
	if err == nil {
		t.Fatal("expected missing-dep error, got nil")
	}
	// The error must mention the missing dependency ID.
	if !strings.Contains(err.Error(), "claim-nonexistent-dep") {
		t.Errorf("expected error to mention missing dep ID, got: %v", err)
	}
}

// TestAdversarial_DuplicateID tries to add two claims with the same ID and
// verifies that AddClaim returns an error on the second add.
func TestAdversarial_DuplicateID(t *testing.T) {
	t.Parallel()
	d := dag.New()
	c := &ir.Claim{ID: "dup", Kind: "lemma"}
	if err := d.AddClaim(c); err != nil {
		t.Fatalf("first AddClaim: %v", err)
	}
	if err := d.AddClaim(c); err == nil {
		t.Fatal("expected error for duplicate ID, got nil")
	}
}

// TestAdversarial_DeepGraph creates a linear chain of 1000 claims and verifies
// that Validate returns nil (no stack overflow) and Closure on the leaf returns
// 999 dependencies.
func TestAdversarial_DeepGraph(t *testing.T) {
	t.Parallel()
	const n = 1000
	d := dag.New()

	// Build chain: claim[0] <- claim[1] <- ... <- claim[n-1]
	// claim[0] has no deps; claim[i] depends on claim[i-1].
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		ids[i] = fmt.Sprintf("claim-%04d", i)
	}

	// Add leaf first (no deps), then each subsequent claim depends on previous.
	for i := 0; i < n; i++ {
		c := &ir.Claim{ID: ids[i], Kind: "lemma"}
		if i > 0 {
			c.DependsOn = []string{ids[i-1]}
		}
		if err := d.AddClaim(c); err != nil {
			t.Fatalf("AddClaim(%q): %v", ids[i], err)
		}
	}

	if err := d.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Closure of the tip (last claim) must contain all 999 prior claims.
	closure, err := d.Closure(ids[n-1])
	if err != nil {
		t.Fatalf("Closure: %v", err)
	}
	if len(closure) != n-1 {
		t.Errorf("expected %d deps in closure, got %d", n-1, len(closure))
	}
}

// TestAdversarial_LargeImpact builds a diamond dependency pattern:
// 1 root, 500 middle claims all depending on root, 1 tip depending on all 500.
// Impact(root) must return all 501 claims; Closure(tip) must return all 501.
func TestAdversarial_LargeImpact(t *testing.T) {
	t.Parallel()
	const midN = 500
	d := dag.New()

	root := &ir.Claim{ID: "root", Kind: "lemma"}
	if err := d.AddClaim(root); err != nil {
		t.Fatalf("AddClaim(root): %v", err)
	}

	midIDs := make([]string, midN)
	for i := 0; i < midN; i++ {
		midIDs[i] = fmt.Sprintf("mid-%04d", i)
		c := &ir.Claim{ID: midIDs[i], Kind: "lemma", DependsOn: []string{"root"}}
		if err := d.AddClaim(c); err != nil {
			t.Fatalf("AddClaim(%q): %v", midIDs[i], err)
		}
	}

	tip := &ir.Claim{ID: "tip", Kind: "lemma", DependsOn: midIDs}
	if err := d.AddClaim(tip); err != nil {
		t.Fatalf("AddClaim(tip): %v", err)
	}

	// Impact(root) = all 500 mid claims + tip = 501.
	impact, err := d.Impact("root")
	if err != nil {
		t.Fatalf("Impact: %v", err)
	}
	if len(impact) != midN+1 {
		t.Errorf("Impact(root): expected %d, got %d", midN+1, len(impact))
	}

	// Closure(tip) = all 500 mid claims + root = 501.
	closure, err := d.Closure("tip")
	if err != nil {
		t.Fatalf("Closure: %v", err)
	}
	if len(closure) != midN+1 {
		t.Errorf("Closure(tip): expected %d, got %d", midN+1, len(closure))
	}
}
