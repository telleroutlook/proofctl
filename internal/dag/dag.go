// Package dag implements the claim dependency DAG for the ProofGraph Engine.
// It provides cycle detection, closure computation, frontier queries, and impact analysis.
package dag

import (
	"fmt"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// DAG manages the directed acyclic graph of proof claims.
type DAG struct {
	claims map[string]*ir.Claim
	order  []string // insertion order
}

// New returns an empty DAG.
func New() *DAG {
	return &DAG{
		claims: make(map[string]*ir.Claim),
	}
}

// AddClaim adds a claim to the DAG.
// It returns an error if a claim with the same ID already exists.
func (d *DAG) AddClaim(c *ir.Claim) error {
	if _, exists := d.claims[c.ID]; exists {
		return fmt.Errorf("dag: duplicate claim ID %q", c.ID)
	}
	d.claims[c.ID] = c
	d.order = append(d.order, c.ID)
	return nil
}

// Claim returns the claim with the given ID, or nil if not found.
func (d *DAG) Claim(id string) *ir.Claim {
	return d.claims[id]
}

// Claims returns all claims in insertion order.
func (d *DAG) Claims() []*ir.Claim {
	out := make([]*ir.Claim, 0, len(d.order))
	for _, id := range d.order {
		out = append(out, d.claims[id])
	}
	return out
}

// Validate checks the DAG for cycles and missing dependency references.
// It uses Kahn's algorithm for cycle detection.
func (d *DAG) Validate() error {
	// Check that all dependency references resolve.
	for id, c := range d.claims {
		for _, dep := range c.DependsOn {
			if _, ok := d.claims[dep]; !ok {
				return fmt.Errorf("dag: claim %q depends on unknown claim %q", id, dep)
			}
		}
	}

	// Kahn's algorithm: compute in-degrees.
	inDegree := make(map[string]int, len(d.claims))
	for id := range d.claims {
		inDegree[id] = 0
	}
	for _, c := range d.claims {
		for _, dep := range c.DependsOn {
			// dep must be processed before c, so c has an in-edge from dep.
			inDegree[c.ID]++
			_ = dep
		}
	}

	// Recompute properly: for each claim, count how many deps it has.
	for id := range d.claims {
		inDegree[id] = len(d.claims[id].DependsOn)
	}

	queue := make([]string, 0, len(d.claims))
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}

	visited := 0
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		visited++

		// Find all claims that depend on curr and reduce their in-degree.
		for id, c := range d.claims {
			for _, dep := range c.DependsOn {
				if dep == curr {
					inDegree[id]--
					if inDegree[id] == 0 {
						queue = append(queue, id)
					}
				}
			}
		}
	}

	if visited != len(d.claims) {
		return fmt.Errorf("dag: cycle detected among %d claims", len(d.claims)-visited)
	}
	return nil
}

// Closure returns the full transitive dependency set of the claim with the given ID.
// The result does not include the claim itself.
func (d *DAG) Closure(id string) ([]string, error) {
	if _, ok := d.claims[id]; !ok {
		return nil, fmt.Errorf("dag: unknown claim %q", id)
	}
	visited := make(map[string]bool)
	d.closure(id, visited)
	delete(visited, id)
	out := make([]string, 0, len(visited))
	for k := range visited {
		out = append(out, k)
	}
	return out, nil
}

func (d *DAG) closure(id string, visited map[string]bool) {
	if visited[id] {
		return
	}
	visited[id] = true
	c, ok := d.claims[id]
	if !ok {
		return
	}
	for _, dep := range c.DependsOn {
		d.closure(dep, visited)
	}
}

// Frontier returns the direct (unresolved) dependencies of the claim with the given ID.
// "Unresolved" means the dep claim has no accepted attestation — this is a structural
// query; callers must pass the set of accepted IDs to filter.
func (d *DAG) Frontier(id string) ([]string, error) {
	c, ok := d.claims[id]
	if !ok {
		return nil, fmt.Errorf("dag: unknown claim %q", id)
	}
	out := make([]string, len(c.DependsOn))
	copy(out, c.DependsOn)
	return out, nil
}

// Impact returns the set of claims that (transitively) depend on the given claim ID.
// The result does not include the claim itself.
func (d *DAG) Impact(id string) ([]string, error) {
	if _, ok := d.claims[id]; !ok {
		return nil, fmt.Errorf("dag: unknown claim %q", id)
	}
	visited := make(map[string]bool)
	for cid, c := range d.claims {
		if cid == id {
			continue
		}
		for _, dep := range c.DependsOn {
			if dep == id {
				d.impactFrom(cid, visited)
				break
			}
		}
	}
	out := make([]string, 0, len(visited))
	for k := range visited {
		out = append(out, k)
	}
	return out, nil
}

// impactFrom collects all claims reachable upward from id (i.e., claims that depend on it).
func (d *DAG) impactFrom(id string, visited map[string]bool) {
	if visited[id] {
		return
	}
	visited[id] = true
	for cid, c := range d.claims {
		if cid == id {
			continue
		}
		for _, dep := range c.DependsOn {
			if dep == id {
				d.impactFrom(cid, visited)
				break
			}
		}
	}
}
