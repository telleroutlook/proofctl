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

	root, _, g, attestations := loadProjectGraph(useJSON)
	pg := loadRawGraph(root, useJSON)

	c := g.Claim(claimID)
	if c == nil {
		die(useJSON, errors.CodeMissingDependency, "unknown claim: "+claimID)
	}

	statuses := status.Compute(g, attestations)
	claimStatus := statuses[claimID]
	att := attestations[claimID]

	// Build suggested fix command(s) for OPEN/BLOCKED claims.
	suggestedFix := buildSuggestedFix(claimID, claimStatus, att, c, pg)

	if useJSON {
		type explainOutput struct {
			ID           string          `json:"id"`
			Kind         string          `json:"kind"`
			Status       string          `json:"status"`
			Assurance    string          `json:"assurance,omitempty"`
			BlockReason  string          `json:"block_reason,omitempty"`
			Statement    ir.Statement    `json:"statement"`
			DependsOn    []string        `json:"depends_on"`
			Attestation  *ir.Attestation `json:"attestation,omitempty"`
			SuggestedFix []string        `json:"suggested_fix,omitempty"`
		}
		out := explainOutput{
			ID:           c.ID,
			Kind:         c.Kind,
			Status:       string(claimStatus),
			Statement:    c.Statement,
			DependsOn:    c.DependsOn,
			SuggestedFix: suggestedFix,
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

	if len(suggestedFix) > 0 {
		fmt.Printf("\nSuggested fix:\n")
		for _, cmd := range suggestedFix {
			fmt.Printf("  %s\n", cmd)
		}
	}
}

// buildSuggestedFix returns copy-pasteable fix commands for OPEN/BLOCKED claims.
func buildSuggestedFix(claimID string, claimStatus ir.Status, att *ir.Attestation, c *ir.Claim, pg *ir.ProofGraph) []string {
	switch claimStatus {
	case ir.StatusAccepted:
		// Check if accepted but missing freshness (C04 risk).
		if att != nil && (att.StartFreshness == "" || att.EndFreshness == "") {
			if c.CheckerPolicy != "" {
				return []string{"proofctl check --claim " + claimID + " --no-cache"}
			}
		}
		return nil
	case ir.StatusOpen, ir.StatusBlocked:
		// No-op: fall through to build fix commands.
	default:
		return nil
	}

	var fixes []string

	if c.CheckerPolicy != "" {
		// Has a checker: suggest check or replay.
		// Build evidence pairs from graph.
		evidenceArgs := buildEvidenceArgs(claimID, c, pg)
		if len(evidenceArgs) > 0 {
			// Prefer replay if evidence digests are known.
			var replayCmd strings.Builder
			fmt.Fprintf(&replayCmd, "proofctl replay --claim %s", claimID)
			for _, e := range evidenceArgs {
				fmt.Fprintf(&replayCmd, " \\\n    --evidence %s --generator %q", e.digest, e.generator)
			}
			if len(evidenceArgs) > 0 && evidenceArgs[0].generator == "" {
				// No generator known — suggest check instead.
				fixes = append(fixes, "proofctl check --claim "+claimID+" --no-cache")
			} else {
				fixes = append(fixes, replayCmd.String())
				fixes = append(fixes, "# or, if certificate already in CAS:")
				fixes = append(fixes, "proofctl check --claim "+claimID+" --no-cache")
			}
		} else {
			fixes = append(fixes, "proofctl check --claim "+claimID+" --no-cache")
		}
	} else {
		// Manual attest claim.
		fixes = append(fixes, "proofctl attest --claim "+claimID+" --outcome accepted --assurance independent-review")
	}

	return fixes
}

type evidenceArg struct {
	digest    string
	generator string
}

// buildEvidenceArgs extracts evidence digests and generator commands for a claim from the graph.
func buildEvidenceArgs(_ string, c *ir.Claim, pg *ir.ProofGraph) []evidenceArg {
	if pg == nil {
		return nil
	}
	// Build evidence index.
	evByDigest := make(map[string]ir.EvidenceDescriptor, len(pg.Evidence))
	for _, ev := range pg.Evidence {
		evByDigest[ev.Digest] = ev
	}
	// Find checker command for this claim's policy.
	checkerCmdParts := []string{}
	for _, ch := range pg.Checkers {
		if ch.ID == c.CheckerPolicy {
			checkerCmdParts = ch.Runtime.Cmd
			break
		}
	}
	hasChecker := len(checkerCmdParts) > 0

	var args []evidenceArg
	for _, ref := range c.Evidence {
		ev, ok := evByDigest[ref]
		if !ok {
			args = append(args, evidenceArg{digest: ref})
			continue
		}
		gen := ""
		if hasChecker && ev.PathHint != "" {
			gen = "${BRIDGE_CHECKER} {cert}"
			_ = checkerCmdParts
		}
		args = append(args, evidenceArg{digest: ev.Digest, generator: gen})
	}
	return args
}
