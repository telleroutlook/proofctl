package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/release"
)

func cmdRelease(args []string, useJSON bool) {
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	_ = fs.String("target", "", "target claim ID (@claim-id)")
	dryRunFlag := fs.Bool("dry-run", false, "dry run (do not write STATUS.json)")
	_ = fs.Parse(args)

	root, cfg, g, attestations := loadProjectGraph(useJSON)

	polPath := filepath.Join(root, cfg.PolicyFile)
	pol := loadPolicy(polPath, useJSON)

	gate := &release.Gate{
		OutputDir:   filepath.Join(root, config.DirName),
		ProjectRoot: root,
	}

	// Load raw graph to access evidence descriptors for manifest generation.
	rawPG := loadRawGraph(root, useJSON)

	type conditionEntry struct {
		ID      string `json:"id"`
		Passed  bool   `json:"passed"`
		Blocker string `json:"blocker,omitempty"`
	}
	type releaseOutput struct {
		Pass          bool              `json:"pass"`
		Blockers      []string          `json:"blockers"`
		Conditions    []conditionEntry  `json:"conditions,omitempty"`
		Released      bool              `json:"released"`
		Defects       map[string]string `json:"defects,omitempty"`
		ReleaseTarget interface{}       `json:"release_target"`
	}

	conditions := release.EvaluateConditions(g, attestations, pol)
	defects := collectDefects(attestations)

	if *dryRunFlag {
		pass, blockers := gate.DryRun(g, attestations, pol)
		if useJSON {
			condEntries := make([]conditionEntry, len(conditions))
			for i, c := range conditions {
				condEntries[i] = conditionEntry{ID: string(c.ID), Passed: c.Passed, Blocker: c.Blocker}
			}
			out := releaseOutput{
				Pass:          pass,
				Blockers:      blockers,
				Conditions:    condEntries,
				Released:      false,
				ReleaseTarget: pol.Target,
			}
			if len(defects) > 0 {
				out.Defects = defects
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(out)
			return
		}
		if pass {
			fmt.Println("RELEASE DRY-RUN: PASS")
			fmt.Printf("release_target: %s\n", pol.Target)
		} else {
			fmt.Printf("RELEASE DRY-RUN: BLOCKED\n\n")
			fmt.Printf("Conditions (%d):\n", len(conditions))
			for _, c := range conditions {
				mark := "PASS"
				if !c.Passed {
					mark = "FAIL"
				}
				if c.Blocker != "" {
					fmt.Printf("  [%s] %s: %s\n", mark, c.ID, c.Blocker)
				} else {
					fmt.Printf("  [%s] %s\n", mark, c.ID)
				}
			}
			fmt.Printf("\nBlockers (%d):\n", len(blockers)+len(defects))
			for _, b := range release.Blockers(conditions) {
				fmt.Printf("  %s\n", b)
			}
			for claimID, reason := range defects {
				fmt.Printf("  [DEFECT] %s: %s\n", claimID, reason)
			}
			fmt.Printf("\nrelease_target: %s (blocked)\n", pol.Target)
		}
		return
	}

	pass, blockers, err := gate.Release(g, attestations, pol, rawPG.Evidence)
	if err != nil {
		die(useJSON, errors.CodeInternalError, err.Error())
	}

	if useJSON {
		condEntries := make([]conditionEntry, len(conditions))
		for i, c := range conditions {
			condEntries[i] = conditionEntry{ID: string(c.ID), Passed: c.Passed, Blocker: c.Blocker}
		}
		out := releaseOutput{
			Pass:          pass,
			Blockers:      blockers,
			Conditions:    condEntries,
			Released:      pass,
			ReleaseTarget: nil,
		}
		if pass {
			out.ReleaseTarget = pol.Target
		}
		if len(defects) > 0 {
			out.Defects = defects
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	if pass {
		fmt.Println("PASS: release gate passed")
		fmt.Printf("release_target: %s\n", pol.Target)
	} else {
		fmt.Printf("RELEASE BLOCKED\n\n")
		fmt.Printf("Conditions (%d):\n", len(conditions))
		for _, c := range conditions {
			mark := "PASS"
			if !c.Passed {
				mark = "FAIL"
			}
			if c.Blocker != "" {
				fmt.Printf("  [%s] %s: %s\n", mark, c.ID, c.Blocker)
			} else {
				fmt.Printf("  [%s] %s\n", mark, c.ID)
			}
		}
		fmt.Printf("\nBlockers (%d):\n", len(blockers)+len(defects))
		for _, b := range blockers {
			fmt.Printf("  [POLICY] %s\n", b)
		}
		for claimID, reason := range defects {
			fmt.Printf("  [DEFECT] %s: %s\n", claimID, reason)
		}
		fmt.Printf("\nrelease_target: %s (blocked)\n", pol.Target)
	}
}

// collectDefects returns a map of claim ID → block_reason for all blocked attestations.
func collectDefects(attestations map[string]*ir.Attestation) map[string]string {
	defects := make(map[string]string)
	for id, att := range attestations {
		if att.BlockReason != "" {
			defects[id] = att.BlockReason
		}
	}
	return defects
}
