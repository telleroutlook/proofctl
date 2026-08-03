package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/status"
	weilpkg "github.com/telleroutlook/proofctl/internal/weil"
)

func cmdExplain(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl explain @<claim-id>")
	}
	claimID := strings.TrimPrefix(args[0], "@")

	_, _, g, attestations := loadProjectGraph(useJSON)

	c := g.Claim(claimID)
	if c == nil {
		die(useJSON, errors.CodeMissingDependency, "unknown claim: "+claimID)
	}

	statuses := status.Compute(g, attestations)
	claimStatus := statuses[claimID]
	att := attestations[claimID]

	if useJSON {
		type explainOutput struct {
			ID          string          `json:"id"`
			Kind        string          `json:"kind"`
			Status      string          `json:"status"`
			Assurance   string          `json:"assurance,omitempty"`
			BlockReason string          `json:"block_reason,omitempty"`
			Statement   ir.Statement    `json:"statement"`
			DependsOn   []string        `json:"depends_on"`
			Attestation *ir.Attestation `json:"attestation,omitempty"`
		}
		out := explainOutput{
			ID:        c.ID,
			Kind:      c.Kind,
			Status:    string(claimStatus),
			Statement: c.Statement,
			DependsOn: c.DependsOn,
		}
		if att != nil {
			out.Assurance = string(att.Assurance)
			out.BlockReason = att.BlockReason
			out.Attestation = att
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	fmt.Printf("Claim:  %s\n", c.ID)
	fmt.Printf("Kind:   %s\n", c.Kind)
	fmt.Printf("Status: %s\n", strings.ToUpper(string(claimStatus)))
	if att != nil {
		assuranceNote := ""
		if att.Assurance == weilpkg.ShadowAssurance {
			assuranceNote = " (shadow mode — not eligible for release)"
		}
		fmt.Printf("Assurance: %s%s\n", att.Assurance, assuranceNote)
		if att.BlockReason != "" {
			fmt.Printf("Block reason: %s\n", att.BlockReason)
		}
	}
	if len(c.DependsOn) > 0 {
		fmt.Printf("Depends on: %s\n", strings.Join(c.DependsOn, ", "))
	}
	if claimStatus == ir.StatusBlocked && att == nil {
		closure, _ := g.Closure(claimID)
		for _, depID := range closure {
			depAtt, ok := attestations[depID]
			if !ok {
				continue
			}
			if ir.Status(depAtt.Outcome) == ir.StatusDisproved ||
				ir.Status(depAtt.Outcome) == ir.StatusRejected ||
				ir.Status(depAtt.Outcome) == ir.StatusError {
				fmt.Printf("Blocker: %s (status: %s)\n", depID, depAtt.Outcome)
			}
		}
	}
}
