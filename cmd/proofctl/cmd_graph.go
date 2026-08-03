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
	_ = fs.Parse(args)

	_, _, g, attestations := loadProjectGraph(useJSON)

	target := strings.TrimPrefix(*targetFlag, "@")

	var statuses map[string]ir.Status
	if *showStatusFlag {
		statuses = status.Compute(g, attestations)
	}

	type claimNode struct {
		ID        string   `json:"id"`
		Kind      string   `json:"kind"`
		Status    string   `json:"status,omitempty"`
		DependsOn []string `json:"depends_on"`
	}

	if useJSON {
		var nodes []claimNode
		claims := g.Claims()
		if target != "" {
			if g.Claim(target) == nil {
				die(useJSON, errors.CodeMissingDependency, "unknown claim: "+target)
			}
			closure, err := g.Closure(target)
			if err != nil {
				die(useJSON, errors.CodeInternalError, err.Error())
			}
			claimSet := make(map[string]bool)
			claimSet[target] = true
			for _, id := range closure {
				claimSet[id] = true
			}
			for _, c := range claims {
				if claimSet[c.ID] {
					node := claimNode{ID: c.ID, Kind: c.Kind, DependsOn: c.DependsOn}
					if statuses != nil {
						node.Status = string(statuses[c.ID])
					}
					nodes = append(nodes, node)
				}
			}
		} else {
			for _, c := range claims {
				node := claimNode{ID: c.ID, Kind: c.Kind, DependsOn: c.DependsOn}
				if statuses != nil {
					node.Status = string(statuses[c.ID])
				}
				nodes = append(nodes, node)
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(nodes)
		return
	}

	claims := g.Claims()
	for _, c := range claims {
		if target != "" {
			closure, err := g.Closure(target)
			if err != nil {
				die(useJSON, errors.CodeInternalError, err.Error())
			}
			claimSet := make(map[string]bool)
			claimSet[target] = true
			for _, id := range closure {
				claimSet[id] = true
			}
			if !claimSet[c.ID] {
				continue
			}
		}
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
