// Package ir defines the Intermediate Representation types for the ProofGraph Engine.
package ir

import "fmt"

// Validate checks resource limits on a Claim.
// It returns an error if any field exceeds the configured maximum.
func (c *Claim) Validate() error {
	if len(c.DependsOn) > MaxClaimDependencies {
		return fmt.Errorf("ir: claim %q has %d dependencies, max is %d", c.ID, len(c.DependsOn), MaxClaimDependencies)
	}
	if len(c.Statement.Text) > MaxClaimTextBytes {
		return fmt.Errorf("ir: claim %q statement text too long: %d bytes, max is %d", c.ID, len(c.Statement.Text), MaxClaimTextBytes)
	}
	if len(c.Evidence) > MaxEvidenceRefs {
		return fmt.Errorf("ir: claim %q has %d evidence refs, max is %d", c.ID, len(c.Evidence), MaxEvidenceRefs)
	}
	if len(c.RequiredAssurance) > MaxAssuranceTypes {
		return fmt.Errorf("ir: claim %q has %d required assurances, max is %d", c.ID, len(c.RequiredAssurance), MaxAssuranceTypes)
	}
	return nil
}

// Validate checks resource limits on a ProofGraph.
// It also validates each individual Claim within the graph.
func (g *ProofGraph) Validate() error {
	if len(g.Claims) > MaxClaimsPerGraph {
		return fmt.Errorf("ir: proof graph has %d claims, max is %d", len(g.Claims), MaxClaimsPerGraph)
	}
	for i := range g.Claims {
		if err := g.Claims[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}
