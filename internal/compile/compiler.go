// Package compile translates source proof descriptions into ProofGraph IR.
package compile

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// Supported source formats.
const (
	FormatJSON = "json"
)

// Compile parses src in the given format and returns a validated ProofGraph.
// Currently only "json" format is supported.
func Compile(src []byte, format string) (*ir.ProofGraph, error) {
	switch format {
	case FormatJSON:
		return compileJSON(src)
	default:
		return nil, fmt.Errorf("compile: unsupported format %q", format)
	}
}

// compileJSON parses a JSON-encoded ProofGraph and performs basic structural validation.
func compileJSON(src []byte) (*ir.ProofGraph, error) {
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.DisallowUnknownFields()

	var pg ir.ProofGraph
	if err := dec.Decode(&pg); err != nil {
		return nil, fmt.Errorf("compile: json decode: %w", err)
	}

	// Enforce resource limits before structural validation.
	if err := pg.Validate(); err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	if err := validate(&pg); err != nil {
		return nil, err
	}
	return &pg, nil
}

// validate performs structural validation on the ProofGraph.
func validate(pg *ir.ProofGraph) error {
	seen := make(map[string]bool, len(pg.Claims))
	for i, c := range pg.Claims {
		if c.ID == "" {
			return fmt.Errorf("compile: claim[%d] has empty ID", i)
		}
		if seen[c.ID] {
			return fmt.Errorf("compile: duplicate claim ID %q", c.ID)
		}
		seen[c.ID] = true
	}

	// Verify all dependency references resolve.
	for _, c := range pg.Claims {
		for _, dep := range c.DependsOn {
			if !seen[dep] {
				return fmt.Errorf("compile: claim %q depends on unknown claim %q", c.ID, dep)
			}
		}
	}

	// Verify all claims in the same batch_group share the same checker_policy.
	groupChecker := make(map[string]string) // batch_group → first checker_policy seen
	for _, c := range pg.Claims {
		if c.BatchGroup == "" {
			continue
		}
		if first, ok := groupChecker[c.BatchGroup]; ok {
			if c.CheckerPolicy != first {
				return fmt.Errorf("compile: batch_group %q: claim %q uses checker_policy %q but group already uses %q",
					c.BatchGroup, c.ID, c.CheckerPolicy, first)
			}
		} else {
			groupChecker[c.BatchGroup] = c.CheckerPolicy
		}
	}

	// Validate cross_domain_deps: IDs must not duplicate depends_on entries
	// (cross-domain deps are separate from intra-graph deps).
	for _, c := range pg.Claims {
		depsSet := make(map[string]bool, len(c.DependsOn))
		for _, d := range c.DependsOn {
			depsSet[d] = true
		}
		for _, xd := range c.CrossDomainDeps {
			if xd == "" {
				return fmt.Errorf("compile: claim %q has empty cross_domain_dep", c.ID)
			}
			if depsSet[xd] {
				return fmt.Errorf("compile: claim %q: cross_domain_dep %q is already in depends_on; use one or the other", c.ID, xd)
			}
		}
	}
	return nil
}
