package policy

import (
	"testing"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// makeGraph builds a DAG with the given claim IDs.
func makeGraph(t *testing.T, ids ...string) *dag.DAG {
	t.Helper()
	d := dag.New()
	for _, id := range ids {
		if err := d.AddClaim(&ir.Claim{ID: id, Kind: "test"}); err != nil {
			t.Fatalf("AddClaim(%q): %v", id, err)
		}
	}
	return d
}

// acceptedAtt returns an Attestation with the accepted outcome for claimID.
func acceptedAtt(claimID string, assurance ir.Assurance) *ir.Attestation {
	return &ir.Attestation{
		ClaimID:   claimID,
		Outcome:   string(ir.StatusAccepted),
		Assurance: assurance,
	}
}

// rejectedAtt returns an Attestation with the rejected outcome.
func rejectedAtt(claimID string, assurance ir.Assurance) *ir.Attestation {
	return &ir.Attestation{
		ClaimID:   claimID,
		Outcome:   string(ir.StatusRejected),
		Assurance: assurance,
	}
}

// TestEvaluateAllAccepted checks that all required claims accepted => pass.
func TestEvaluateAllAccepted(t *testing.T) {
	t.Parallel()
	graph := makeGraph(t, "c1", "c2")
	atts := map[string]*ir.Attestation{
		"c1": acceptedAtt("c1", ir.AssuranceFormalKernel),
		"c2": acceptedAtt("c2", ir.AssuranceFormalKernel),
	}
	pol := ReleasePolicy{
		Version:        "v1",
		Target:         "main",
		RequiredClaims: []string{"c1", "c2"},
	}
	pass, blockers := Evaluate(graph, atts, pol)
	if !pass {
		t.Errorf("expected pass, got blockers: %v", blockers)
	}
	if len(blockers) != 0 {
		t.Errorf("expected no blockers, got: %v", blockers)
	}
}

// TestEvaluateMissingAttestation checks that a missing attestation for a required claim blocks.
func TestEvaluateMissingAttestation(t *testing.T) {
	t.Parallel()
	graph := makeGraph(t, "c1")
	atts := map[string]*ir.Attestation{}
	pol := ReleasePolicy{
		RequiredClaims: []string{"c1"},
	}
	pass, blockers := Evaluate(graph, atts, pol)
	if pass {
		t.Error("expected fail, got pass")
	}
	if len(blockers) == 0 {
		t.Error("expected at least one blocker")
	}
}

// TestEvaluateRequiredClaimNotInGraph checks that a required claim missing from the graph blocks.
func TestEvaluateRequiredClaimNotInGraph(t *testing.T) {
	t.Parallel()
	graph := makeGraph(t) // empty graph
	atts := map[string]*ir.Attestation{}
	pol := ReleasePolicy{
		RequiredClaims: []string{"nonexistent"},
	}
	pass, blockers := Evaluate(graph, atts, pol)
	if pass {
		t.Error("expected fail for claim not in graph, got pass")
	}
	if len(blockers) == 0 {
		t.Error("expected at least one blocker")
	}
}

// TestEvaluateEmptyPolicy checks that an empty policy against an empty graph passes.
func TestEvaluateEmptyPolicy(t *testing.T) {
	t.Parallel()
	graph := makeGraph(t)
	atts := map[string]*ir.Attestation{}
	pol := ReleasePolicy{}
	pass, blockers := Evaluate(graph, atts, pol)
	if !pass {
		t.Errorf("expected pass for empty policy, got blockers: %v", blockers)
	}
}

// TestEvaluateMixedConditions checks that all blockers are reported for mixed conditions.
func TestEvaluateMixedConditions(t *testing.T) {
	t.Parallel()
	graph := makeGraph(t, "c1", "c2")
	atts := map[string]*ir.Attestation{
		// c1 is accepted.
		"c1": acceptedAtt("c1", ir.AssuranceAIReview),
		// c2 is rejected.
		"c2": rejectedAtt("c2", ir.AssuranceFormalKernel),
	}
	pol := ReleasePolicy{
		RequiredClaims: []string{"c1", "c2"},
	}
	pass, blockers := Evaluate(graph, atts, pol)
	if pass {
		t.Error("expected fail for mixed conditions, got pass")
	}
	// Should have exactly 1 blocker: c2 not accepted.
	if len(blockers) != 1 {
		t.Errorf("expected 1 blocker, got %d: %v", len(blockers), blockers)
	}
}

// TestEvaluateRejectedRequiredClaim checks that a rejected attestation for a required claim blocks.
func TestEvaluateRejectedRequiredClaim(t *testing.T) {
	t.Parallel()
	graph := makeGraph(t, "c1")
	atts := map[string]*ir.Attestation{
		"c1": rejectedAtt("c1", ir.AssuranceFormalKernel),
	}
	pol := ReleasePolicy{
		RequiredClaims: []string{"c1"},
	}
	pass, blockers := Evaluate(graph, atts, pol)
	if pass {
		t.Error("expected fail for rejected required claim, got pass")
	}
	if len(blockers) == 0 {
		t.Error("expected at least one blocker")
	}
}
