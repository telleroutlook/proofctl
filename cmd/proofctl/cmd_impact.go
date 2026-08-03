package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	errors "github.com/telleroutlook/proofctl/internal/errors"
)

func cmdImpact(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl impact @<claim-id>")
	}
	claimID := strings.TrimPrefix(args[0], "@")

	_, _, g, _ := loadProjectGraph(useJSON)

	if g.Claim(claimID) == nil {
		die(useJSON, errors.CodeMissingDependency, "unknown claim: "+claimID)
	}

	impact, err := g.Impact(claimID)
	if err != nil {
		die(useJSON, errors.CodeInternalError, err.Error())
	}
	sort.Strings(impact)

	if useJSON {
		type impactOutput struct {
			Claim  string   `json:"claim"`
			Impact []string `json:"impact"`
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(impactOutput{Claim: claimID, Impact: impact})
		return
	}

	if len(impact) == 0 {
		fmt.Printf("No claims depend on %s\n", claimID)
		return
	}
	fmt.Printf("Claims that depend on %s:\n", claimID)
	for _, id := range impact {
		fmt.Printf("  %s\n", id)
	}
}
