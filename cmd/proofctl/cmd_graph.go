package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/status"
)

func cmdGraph(args []string, useJSON bool) {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	targetFlag := fs.String("target", "", "show closure for @claim-id")
	showStatusFlag := fs.Bool("show-status", false, "show claim status inline")
	dotFlag := fs.Bool("dot", false, "output Graphviz DOT format")
	mermaidFlag := fs.Bool("mermaid", false, "output Mermaid flowchart format")
	_ = fs.Parse(args)

	_, _, g, attestations := loadProjectGraph(useJSON)

	target := strings.TrimPrefix(*targetFlag, "@")

	var statuses map[string]ir.Status
	if *showStatusFlag || *dotFlag || *mermaidFlag {
		statuses = status.Compute(g, attestations)
	}

	// Build filtered claim list.
	allClaims := g.Claims()
	var claims []*ir.Claim
	if target != "" {
		if g.Claim(target) == nil {
			die(useJSON, errors.CodeMissingDependency, "unknown claim: "+target)
		}
		closure, err := g.Closure(target)
		if err != nil {
			die(useJSON, errors.CodeInternalError, err.Error())
		}
		claimSet := make(map[string]bool, len(closure)+1)
		claimSet[target] = true
		for _, id := range closure {
			claimSet[id] = true
		}
		for _, c := range allClaims {
			if claimSet[c.ID] {
				claims = append(claims, c)
			}
		}
	} else {
		claims = allClaims
	}

	if *dotFlag {
		printDOT(claims, statuses)
		return
	}
	if *mermaidFlag {
		printMermaid(claims, statuses)
		return
	}

	type claimNode struct {
		ID        string   `json:"id"`
		Kind      string   `json:"kind"`
		Status    string   `json:"status,omitempty"`
		DependsOn []string `json:"depends_on"`
	}

	if useJSON {
		var nodes []claimNode
		for _, c := range claims {
			node := claimNode{ID: c.ID, Kind: c.Kind, DependsOn: c.DependsOn}
			if statuses != nil {
				node.Status = string(statuses[c.ID])
			}
			nodes = append(nodes, node)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(nodes)
		return
	}

	for _, c := range claims {
		deps := strings.Join(c.DependsOn, ", ")
		if deps == "" {
			deps = "(no deps)"
		}
		if statuses != nil {
			fmt.Printf("%s [%s] %s -> %s\n", c.ID, c.Kind, strings.ToUpper(string(statuses[c.ID])), deps)
		} else {
			fmt.Printf("%s [%s] -> %s\n", c.ID, c.Kind, deps)
		}
	}
}

// statusDotColor maps a claim status to a Graphviz node color.
func statusDotColor(s ir.Status) string {
	switch s {
	case ir.StatusAccepted:
		return "green"
	case ir.StatusRejected:
		return "red"
	case ir.StatusBlocked:
		return "orange"
	default:
		return "lightgray"
	}
}

// statusMermaidStyle maps a claim status to a Mermaid node style class.
func statusMermaidStyle(s ir.Status) string {
	switch s {
	case ir.StatusAccepted:
		return "accepted"
	case ir.StatusRejected:
		return "rejected"
	case ir.StatusBlocked:
		return "blocked"
	default:
		return "open"
	}
}

// mermaidID converts a claim ID to a Mermaid-safe node identifier.
func mermaidID(id string) string {
	r := strings.NewReplacer("-", "_", ".", "_")
	return r.Replace(id)
}

func printDOT(claims []*ir.Claim, statuses map[string]ir.Status) {
	fmt.Println("digraph proofgraph {")
	fmt.Println("  rankdir=BT;")
	fmt.Println("  node [shape=box, style=filled];")
	for _, c := range claims {
		color := "lightgray"
		if statuses != nil {
			color = statusDotColor(statuses[c.ID])
		}
		label := c.ID
		if statuses != nil {
			label = fmt.Sprintf("%s\\n[%s]", c.ID, strings.ToUpper(string(statuses[c.ID])))
		}
		fmt.Printf("  %q [label=%q, fillcolor=%s];\n", c.ID, label, color)
	}
	for _, c := range claims {
		for _, dep := range c.DependsOn {
			fmt.Printf("  %q -> %q;\n", c.ID, dep)
		}
	}
	fmt.Println("}")
}

func printMermaid(claims []*ir.Claim, statuses map[string]ir.Status) {
	fmt.Println("flowchart BT")
	if statuses != nil {
		fmt.Println("  classDef accepted fill:#a8d8a8,stroke:#4a7c59")
		fmt.Println("  classDef rejected fill:#f4a5a5,stroke:#a33")
		fmt.Println("  classDef blocked fill:#ffd8a8,stroke:#b36b00")
		fmt.Println("  classDef open fill:#e0e0e0,stroke:#888")
	}
	for _, c := range claims {
		label := c.ID
		if statuses != nil {
			label = fmt.Sprintf("%s<br/>[%s]", c.ID, strings.ToUpper(string(statuses[c.ID])))
		}
		fmt.Printf("  %s[\"%s\"]\n", mermaidID(c.ID), label)
	}
	for _, c := range claims {
		for _, dep := range c.DependsOn {
			fmt.Printf("  %s --> %s\n", mermaidID(c.ID), mermaidID(dep))
		}
	}
	if statuses != nil {
		for _, c := range claims {
			fmt.Printf("  class %s %s\n", mermaidID(c.ID), statusMermaidStyle(statuses[c.ID]))
		}
	}
}
