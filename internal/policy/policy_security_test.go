package policy_test

import (
	"testing"

	"github.com/telleroutlook/proofctl/internal/dag"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
)

// secMakeGraph builds a DAG with the given claim IDs (no deps).
func secMakeGraph(t *testing.T, ids ...string) *dag.DAG {
	t.Helper()
	d := dag.New()
	for _, id := range ids {
		if err := d.AddClaim(&ir.Claim{ID: id, Kind: "test"}); err != nil {
			t.Fatalf("AddClaim(%q): %v", id, err)
		}
	}
	return d
}

// secAcceptedAtt returns an Attestation with the accepted outcome.
func secAcceptedAtt(claimID string, assurance ir.Assurance) *ir.Attestation {
	return &ir.Attestation{
		ClaimID:   claimID,
		Outcome:   string(ir.StatusAccepted),
		Assurance: assurance,
	}
}

// TestAdversarial_MissingRequiredClaim checks that a required claim with no
// attestation blocks the policy.
func TestAdversarial_MissingRequiredClaim(t *testing.T) {
	t.Parallel()
	graph := secMakeGraph(t, "c1", "c2")
	// Only c1 attested; c2 is missing.
	atts := map[string]*ir.Attestation{
		"c1": secAcceptedAtt("c1", ir.AssuranceFormalKernel),
	}
	pol := policy.ReleasePolicy{
		Version:        "1",
		Target:         "test-target",
		RequiredClaims: []string{"c1", "c2"},
	}
	pass, blockers := policy.Evaluate(graph, atts, pol)
	if pass {
		t.Error("expected fail for missing required claim, got pass")
	}
	if len(blockers) == 0 {
		t.Error("expected at least one blocker for missing claim")
	}
}

// TestAdversarial_EmptyAllowedList checks that a policy with empty
// allowed_assurances (meaning allow all) and no forbidden assurances passes
// for any assurance type — assurance enforcement is C03's responsibility.
func TestAdversarial_EmptyAllowedList(t *testing.T) {
	t.Parallel()
	assurances := []ir.Assurance{
		ir.AssuranceFormalKernel,
		ir.AssuranceDeterministicCAP,
		ir.AssuranceExactReplay,
		ir.AssuranceReproducibleComputation,
		ir.AssuranceIndependentReview,
		ir.AssuranceAIReview,
		ir.AssuranceAssumption,
	}
	for _, assurance := range assurances {
		assurance := assurance
		t.Run(string(assurance), func(t *testing.T) {
			t.Parallel()
			graph := secMakeGraph(t, "c1")
			atts := map[string]*ir.Attestation{
				"c1": secAcceptedAtt("c1", assurance),
			}
			pol := policy.ReleasePolicy{
				Version:        "1",
				Target:         "test-target",
				RequiredClaims: []string{"c1"},
			}
			pass, blockers := policy.Evaluate(graph, atts, pol)
			if !pass {
				t.Errorf("assurance %q: expected pass (Evaluate does not check assurances), got blockers: %v",
					assurance, blockers)
			}
		})
	}
}
