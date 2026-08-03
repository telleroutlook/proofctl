package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
)

func cmdFrontier(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl frontier @<claim-id>")
	}
	claimID := strings.TrimPrefix(args[0], "@")

	_, _, g, attestations := loadProjectGraph(useJSON)

	if g.Claim(claimID) == nil {
		die(useJSON, errors.CodeMissingDependency, "unknown claim: "+claimID)
	}

	directDeps, err := g.Frontier(claimID)
	if err != nil {
		die(useJSON, errors.CodeInternalError, err.Error())
	}

	var frontier []string
	for _, depID := range directDeps {
		att, ok := attestations[depID]
		if !ok || att.Outcome != string(ir.StatusAccepted) {
			frontier = append(frontier, depID)
		}
	}
	sort.Strings(frontier)

	if useJSON {
		type frontierOutput struct {
			Claim    string   `json:"claim"`
			Frontier []string `json:"frontier"`
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(frontierOutput{Claim: claimID, Frontier: frontier})
		return
	}

	if len(frontier) == 0 {
		fmt.Printf("No unresolved direct dependencies for %s\n", claimID)
		return
	}
	fmt.Printf("Unresolved direct dependencies of %s:\n", claimID)
	for _, dep := range frontier {
		fmt.Printf("  %s\n", dep)
	}
}
