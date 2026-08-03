package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"flag"
	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/compile"
	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/runner"
	"github.com/telleroutlook/proofctl/internal/verify"
)

// cmdVerify implements the verify subcommand.
//
// Usage:
//
//	proofctl verify @<claim-id>
//	proofctl verify --project
func cmdVerify(args []string, useJSON bool) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	projectFlag := fs.Bool("project", false, "verify all open claims in dependency order")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "verify: "+err.Error())
	}

	root, _, g, _ := loadProjectGraph(useJSON)

	casRoot := filepath.Join(root, config.DirName, config.CASDir)
	store, err := cas.New(casRoot)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "cannot open CAS: "+err.Error())
	}

	attestDir := filepath.Join(root, config.DirName, config.AttestDir)

	nr := &runner.NativeRunner{}
	pipe := &verify.Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner:    nr,
	}

	var targets []string
	if *projectFlag {
		order, err := topoSort(g)
		if err != nil {
			die(useJSON, errors.CodeCycleDetected, err.Error())
		}
		attestations := loadAttestations(root, useJSON)
		for _, id := range order {
			att, ok := attestations[id]
			if ok && att.Outcome == string(ir.StatusAccepted) {
				continue
			}
			targets = append(targets, id)
		}
	} else {
		if len(fs.Args()) == 0 {
			die(useJSON, errors.CodeInvalidInput, "usage: proofctl verify @<claim-id> or --project")
		}
		targets = []string{strings.TrimPrefix(fs.Args()[0], "@")}
	}

	type verifyResult struct {
		ClaimID   string `json:"claim_id"`
		Outcome   string `json:"outcome"`
		Assurance string `json:"assurance"`
		CacheHit  bool   `json:"cache_hit"`
		Error     string `json:"error,omitempty"`
	}

	var results []verifyResult
	exitCode := 0

	for _, claimID := range targets {
		claim := g.Claim(claimID)
		if claim == nil {
			if useJSON {
				results = append(results, verifyResult{ClaimID: claimID, Outcome: "error", Error: "unknown claim"})
			} else {
				fmt.Printf("ERROR %s: unknown claim\n", claimID)
			}
			exitCode = 1
			continue
		}

		pg := loadRawGraph(root, useJSON)
		checkerID, found := findChecker(pg, claim.CheckerPolicy)
		if !found {
			if useJSON {
				results = append(results, verifyResult{ClaimID: claimID, Outcome: "error", Error: "no checker for policy " + claim.CheckerPolicy})
			} else {
				fmt.Printf("ERROR %s: no checker for policy %q\n", claimID, claim.CheckerPolicy)
			}
			exitCode = 1
			continue
		}

		evidence := findEvidence(pg, claim.Evidence)

		res, runErr := pipe.Run(context.Background(), claimID, checkerID, evidence, "")
		if runErr != nil {
			if useJSON {
				results = append(results, verifyResult{ClaimID: claimID, Outcome: "error", Error: runErr.Error()})
			} else {
				fmt.Printf("FAIL %s: %v\n", claimID, runErr)
			}
			exitCode = 1
			continue
		}

		cacheNote := ""
		if res.CacheHit {
			cacheNote = " [cache-hit]"
		}
		if useJSON {
			results = append(results, verifyResult{
				ClaimID:   claimID,
				Outcome:   res.Attestation.Outcome,
				Assurance: string(res.Attestation.Assurance),
				CacheHit:  res.CacheHit,
			})
		} else {
			if res.Attestation.Outcome == "accepted" {
				fmt.Printf("PASS %s%s\n", claimID, cacheNote)
			} else {
				fmt.Printf("FAIL %s: outcome=%s%s\n", claimID, res.Attestation.Outcome, cacheNote)
				exitCode = 1
			}
		}
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	}

	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

// loadRawGraph loads the raw ProofGraph (with Checkers + Evidence lists).
func loadRawGraph(root string, useJSON bool) *ir.ProofGraph {
	graphPath := filepath.Join(root, config.DirName, config.GraphFile)
	data, err := os.ReadFile(graphPath)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "cannot read graph.json: "+err.Error())
	}
	pg, err := compile.Compile(data, compile.FormatJSON)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, "graph.json invalid: "+err.Error())
	}
	return pg
}

// findChecker returns the CheckerIdentity whose ID matches checkerPolicy.
func findChecker(pg *ir.ProofGraph, checkerPolicy string) (ir.CheckerIdentity, bool) {
	for _, ch := range pg.Checkers {
		if ch.ID == checkerPolicy {
			return ch, true
		}
	}
	return ir.CheckerIdentity{}, false
}

// findEvidence returns the EvidenceDescriptors whose digests match the refs.
func findEvidence(pg *ir.ProofGraph, refs []string) []ir.EvidenceDescriptor {
	refSet := make(map[string]struct{}, len(refs))
	for _, r := range refs {
		refSet[r] = struct{}{}
	}
	var out []ir.EvidenceDescriptor
	for _, ev := range pg.Evidence {
		if _, ok := refSet[ev.Digest]; ok {
			out = append(out, ev)
		}
	}
	return out
}
