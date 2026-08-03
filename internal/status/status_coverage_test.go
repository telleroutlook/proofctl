package status

import (
	"testing"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// attWithReason builds an Attestation with a specific block reason.
func attWithReason(claimID string, outcome ir.Status, reason string) *ir.Attestation {
	return &ir.Attestation{
		ClaimID:     claimID,
		Outcome:     string(outcome),
		Assurance:   ir.AssuranceFormalKernel,
		BlockReason: reason,
	}
}

// TestComputeWithReasons_Accepted checks that an accepted claim has no block reason.
func TestComputeWithReasons_Accepted(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "c1")
	atts := map[string]*ir.Attestation{"c1": att("c1", ir.StatusAccepted)}

	result := ComputeWithReasons(d, atts)
	cs := result["c1"]
	if cs.Status != ir.StatusAccepted {
		t.Errorf("expected accepted, got %q", cs.Status)
	}
	if cs.BlockReason != "" {
		t.Errorf("expected empty block reason, got %q", cs.BlockReason)
	}
}

// TestComputeWithReasons_BlockedWithReason checks that BlockReason is propagated
// when a direct attestation has outcome=blocked and a reason set.
func TestComputeWithReasons_BlockedWithReason(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "c1")
	atts := map[string]*ir.Attestation{
		"c1": attWithReason("c1", ir.StatusBlocked, "defect D4"),
	}

	result := ComputeWithReasons(d, atts)
	cs := result["c1"]
	if cs.Status != ir.StatusBlocked {
		t.Errorf("expected blocked, got %q", cs.Status)
	}
	if cs.BlockReason != "defect D4" {
		t.Errorf("expected block reason %q, got %q", "defect D4", cs.BlockReason)
	}
}

// TestComputeWithReasons_BlockedByDep checks that BlockReason is propagated
// from a transitive dependency attestation when no direct attestation exists.
func TestComputeWithReasons_BlockedByDep(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "dep")
	addClaim(t, d, "c1", "dep")
	atts := map[string]*ir.Attestation{
		"dep": attWithReason("dep", ir.StatusDisproved, "counterexample found"),
	}

	result := ComputeWithReasons(d, atts)
	cs := result["c1"]
	if cs.Status != ir.StatusBlocked {
		t.Errorf("c1: expected blocked, got %q", cs.Status)
	}
	if cs.BlockReason != "counterexample found" {
		t.Errorf("c1: expected block reason %q, got %q", "counterexample found", cs.BlockReason)
	}
}

// TestComputeWithReasons_BlockedByDepNoReason checks that when a blocking dep has
// no BlockReason, the dep's claim ID is used as the reason.
func TestComputeWithReasons_BlockedByDepNoReason(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "dep-id")
	addClaim(t, d, "c1", "dep-id")
	atts := map[string]*ir.Attestation{
		"dep-id": att("dep-id", ir.StatusRejected),
	}

	result := ComputeWithReasons(d, atts)
	cs := result["c1"]
	if cs.Status != ir.StatusBlocked {
		t.Errorf("c1: expected blocked, got %q", cs.Status)
	}
	if cs.BlockReason != "dep-id" {
		t.Errorf("c1: expected block reason %q (dep ID), got %q", "dep-id", cs.BlockReason)
	}
}

// TestComputeWithReasons_EmptyGraph checks that ComputeWithReasons on an empty graph
// returns an empty map.
func TestComputeWithReasons_EmptyGraph(t *testing.T) {
	t.Parallel()
	d := dag.New()
	result := ComputeWithReasons(d, map[string]*ir.Attestation{})
	if len(result) != 0 {
		t.Errorf("expected empty map for empty graph, got %v", result)
	}
}

// TestComputeWithReasons_OpenNoDeps checks that a claim with no attestation and no
// dependencies is open with no block reason.
func TestComputeWithReasons_OpenNoDeps(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "c1")
	result := ComputeWithReasons(d, map[string]*ir.Attestation{})
	cs := result["c1"]
	if cs.Status != ir.StatusOpen {
		t.Errorf("expected open, got %q", cs.Status)
	}
	if cs.BlockReason != "" {
		t.Errorf("expected empty block reason, got %q", cs.BlockReason)
	}
}

// TestComputeWithReasons_FiveClaimChain checks that a 5-claim chain where the
// middle claim is disproved causes all upward claims to be blocked.
//
// Chain: leaf -> mid2 -> [disproved] -> mid1 -> top
func TestComputeWithReasons_FiveClaimChain(t *testing.T) {
	t.Parallel()
	d := dag.New()
	addClaim(t, d, "leaf")
	addClaim(t, d, "mid1", "leaf")
	addClaim(t, d, "bad", "mid1")   // this one is disproved
	addClaim(t, d, "mid2", "bad")
	addClaim(t, d, "top", "mid2")

	atts := map[string]*ir.Attestation{
		"leaf": att("leaf", ir.StatusAccepted),
		"mid1": att("mid1", ir.StatusAccepted),
		"bad":  attWithReason("bad", ir.StatusDisproved, "D18 counterexample"),
	}

	result := ComputeWithReasons(d, atts)

	if result["leaf"].Status != ir.StatusAccepted {
		t.Errorf("leaf: expected accepted, got %q", result["leaf"].Status)
	}
	if result["mid1"].Status != ir.StatusAccepted {
		t.Errorf("mid1: expected accepted, got %q", result["mid1"].Status)
	}
	if result["bad"].Status != ir.StatusDisproved {
		t.Errorf("bad: expected disproved, got %q", result["bad"].Status)
	}
	if result["mid2"].Status != ir.StatusBlocked {
		t.Errorf("mid2: expected blocked, got %q", result["mid2"].Status)
	}
	if result["top"].Status != ir.StatusBlocked {
		t.Errorf("top: expected blocked, got %q", result["top"].Status)
	}
	// Block reason must propagate from the "bad" claim's attestation.
	if result["mid2"].BlockReason != "D18 counterexample" {
		t.Errorf("mid2: expected block reason %q, got %q", "D18 counterexample", result["mid2"].BlockReason)
	}
}

// TestComputeWithReasons_AllClaimsPresent checks that ComputeWithReasons returns
// a status entry for every claim in the graph.
func TestComputeWithReasons_AllClaimsPresent(t *testing.T) {
	t.Parallel()
	d := dag.New()
	ids := []string{"x", "y", "z"}
	for _, id := range ids {
		addClaim(t, d, id)
	}
	result := ComputeWithReasons(d, map[string]*ir.Attestation{})
	for _, id := range ids {
		if _, ok := result[id]; !ok {
			t.Errorf("missing status for claim %q", id)
		}
	}
}
