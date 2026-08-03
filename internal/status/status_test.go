package status

import (
	"testing"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// addClaim is a helper that adds a claim to the DAG and fatals on error.
func addClaim(t *testing.T, d *dag.DAG, id string, deps ...string) {
	t.Helper()
	if err := d.AddClaim(&ir.Claim{ID: id, Kind: "test", DependsOn: deps}); err != nil {
		t.Fatalf("AddClaim(%q): %v", id, err)
	}
}

// att returns an Attestation for claimID with the given outcome and assurance.
func att(claimID string, outcome ir.Status) *ir.Attestation {
	return &ir.Attestation{
		ClaimID:   claimID,
		Outcome:   string(outcome),
		Assurance: ir.AssuranceFormalKernel,
	}
}

// TestComputeAccepted checks that a claim with an accepted attestation is accepted.
func TestComputeAccepted(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "c1")
	atts := map[string]*ir.Attestation{"c1": att("c1", ir.StatusAccepted)}

	statuses := Compute(d, atts)
	if got := statuses["c1"]; got != ir.StatusAccepted {
		t.Errorf("expected accepted, got %q", got)
	}
}

// TestComputeRejected checks that a claim with a rejected attestation is rejected.
func TestComputeRejected(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "c1")
	atts := map[string]*ir.Attestation{"c1": att("c1", ir.StatusRejected)}

	statuses := Compute(d, atts)
	if got := statuses["c1"]; got != ir.StatusRejected {
		t.Errorf("expected rejected, got %q", got)
	}
}

// TestComputeOpen checks that a claim with no attestation and no deps is open.
func TestComputeOpen(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "c1")
	atts := map[string]*ir.Attestation{}

	statuses := Compute(d, atts)
	if got := statuses["c1"]; got != ir.StatusOpen {
		t.Errorf("expected open, got %q", got)
	}
}

// TestComputeBlockedByRejectedDep checks that a claim with a rejected dep is blocked.
func TestComputeBlockedByRejectedDep(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "dep")
	addClaim(t, d, "c1", "dep")
	atts := map[string]*ir.Attestation{"dep": att("dep", ir.StatusRejected)}

	statuses := Compute(d, atts)
	if got := statuses["c1"]; got != ir.StatusBlocked {
		t.Errorf("expected blocked, got %q", got)
	}
}

// TestComputeBlockedByDisprovedDep checks that a claim with a disproved dep is blocked.
func TestComputeBlockedByDisprovedDep(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "dep")
	addClaim(t, d, "c1", "dep")
	atts := map[string]*ir.Attestation{"dep": att("dep", ir.StatusDisproved)}

	statuses := Compute(d, atts)
	if got := statuses["c1"]; got != ir.StatusBlocked {
		t.Errorf("expected blocked for disproved dep, got %q", got)
	}
}

// TestComputeAttestationOverridesBlockedDep checks that an attestation overrides a blocked dep.
func TestComputeAttestationOverridesBlockedDep(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "dep")
	addClaim(t, d, "c1", "dep")
	// dep is rejected, but c1 has an accepted attestation.
	atts := map[string]*ir.Attestation{
		"dep": att("dep", ir.StatusRejected),
		"c1":  att("c1", ir.StatusAccepted),
	}

	statuses := Compute(d, atts)
	if got := statuses["c1"]; got != ir.StatusAccepted {
		t.Errorf("expected accepted (attestation wins over blocked dep), got %q", got)
	}
}

// TestComputeChainBlockedTransitively checks that blocking propagates through a chain.
// A <- B <- C where A is rejected: B=blocked, C=blocked.
func TestComputeChainBlockedTransitively(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "a")
	addClaim(t, d, "b", "a")
	addClaim(t, d, "c", "b")
	atts := map[string]*ir.Attestation{
		"a": att("a", ir.StatusRejected),
	}

	statuses := Compute(d, atts)

	if got := statuses["a"]; got != ir.StatusRejected {
		t.Errorf("a: expected rejected, got %q", got)
	}
	if got := statuses["b"]; got != ir.StatusBlocked {
		t.Errorf("b: expected blocked, got %q", got)
	}
	if got := statuses["c"]; got != ir.StatusBlocked {
		t.Errorf("c: expected blocked, got %q", got)
	}
}

// TestComputeAllClaims checks that Compute returns a status for every claim in the graph.
func TestComputeAllClaims(t *testing.T) {
	t.Parallel()
	d := dag.New()
	ids := []string{"a", "b", "c"}
	for _, id := range ids {
		addClaim(t, d, id)
	}
	statuses := Compute(d, map[string]*ir.Attestation{})
	for _, id := range ids {
		if _, ok := statuses[id]; !ok {
			t.Errorf("missing status for claim %q", id)
		}
	}
}

// TestComputeEmptyGraph checks that Compute on an empty graph returns an empty map.
func TestComputeEmptyGraph(t *testing.T) {
	t.Parallel()
	d := dag.New()
	statuses := Compute(d, map[string]*ir.Attestation{})
	if len(statuses) != 0 {
		t.Errorf("expected empty status map for empty graph, got %v", statuses)
	}
}

// TestComputeOpenChainNoDeps checks that a multi-node graph with no attestations is all open.
func TestComputeOpenChainNoDeps(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "leaf")
	addClaim(t, d, "mid", "leaf")
	addClaim(t, d, "top", "mid")
	statuses := Compute(d, map[string]*ir.Attestation{})
	for _, id := range []string{"leaf", "mid", "top"} {
		if got := statuses[id]; got != ir.StatusOpen {
			t.Errorf("%s: expected open, got %q", id, got)
		}
	}
}
