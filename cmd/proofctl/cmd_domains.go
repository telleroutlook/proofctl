package main

import (
	"encoding/json"
	"fmt"
	"os"

	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/scaffold"
)

func cmdDomains(args []string, useJSON bool) {
	if len(args) == 0 || args[0] != "list" {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl domains list")
	}

	if useJSON {
		type domainEntry struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			HasBridge   bool   `json:"has_bridge"`
			HasPolicy   bool   `json:"has_policy"`
			HasGraph    bool   `json:"has_graph"`
		}
		entries := make([]domainEntry, len(scaffold.KnownDomains))
		for i, d := range scaffold.KnownDomains {
			entries[i] = domainEntry{
				Name:        d.Name,
				Description: d.Description,
				HasBridge:   d.BridgeSrc != "",
				HasPolicy:   d.PolicyTemplate != "",
				HasGraph:    d.GraphTemplate != "",
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(entries)
		return
	}

	fmt.Printf("%-8s  %-6s  %-6s  %-6s  %s\n", "DOMAIN", "BRIDGE", "POLICY", "GRAPH", "DESCRIPTION")
	fmt.Printf("%-8s  %-6s  %-6s  %-6s  %s\n", "------", "------", "------", "-----", "-----------")
	for _, d := range scaffold.KnownDomains {
		bridge := "no"
		if d.BridgeSrc != "" {
			bridge = "yes"
		}
		policy := "no"
		if d.PolicyTemplate != "" {
			policy = "yes"
		}
		graph := "no"
		if d.GraphTemplate != "" {
			graph = "yes"
		}
		fmt.Printf("%-8s  %-6s  %-6s  %-6s  %s\n", d.Name, bridge, policy, graph, d.Description)
	}
}
