package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

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
//	proofctl verify --project [--parallel N]
func cmdVerify(args []string, useJSON bool) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	projectFlag := fs.Bool("project", false, "verify all open claims in dependency order")
	parallelFlag := fs.Int("parallel", 0, "max parallel checkers for --project (0 = number of CPUs)")
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
	nr := &runner.NativeRunner{ProjectRoot: root}
	pipe := &verify.Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner:    nr,
	}

	type verifyResult struct {
		ClaimID   string `json:"claim_id"`
		Outcome   string `json:"outcome"`
		Assurance string `json:"assurance"`
		CacheHit  bool   `json:"cache_hit"`
		Error     string `json:"error,omitempty"`
	}

	printResult := func(res verifyResult) {
		cacheNote := ""
		if res.CacheHit {
			cacheNote = " [cache-hit]"
		}
		switch {
		case res.Error != "":
			fmt.Printf("ERROR %s: %s\n", res.ClaimID, res.Error)
		case res.Outcome == "accepted":
			fmt.Printf("PASS %s%s\n", res.ClaimID, cacheNote)
		default:
			fmt.Printf("FAIL %s: outcome=%s%s\n", res.ClaimID, res.Outcome, cacheNote)
		}
	}

	runOne := func(claimID string) verifyResult {
		claim := g.Claim(claimID)
		if claim == nil {
			return verifyResult{ClaimID: claimID, Outcome: "error", Error: "unknown claim"}
		}
		pg := loadRawGraph(root, useJSON)
		checkerID, found := findChecker(pg, claim.CheckerPolicy)
		if !found {
			return verifyResult{ClaimID: claimID, Outcome: "error", Error: "no checker for policy " + claim.CheckerPolicy}
		}
		evidence := findEvidence(pg, claim.Evidence)
		res, runErr := pipe.Run(context.Background(), claimID, checkerID, evidence, "")
		if runErr != nil {
			return verifyResult{ClaimID: claimID, Outcome: "error", Error: runErr.Error()}
		}
		return verifyResult{
			ClaimID:   claimID,
			Outcome:   res.Attestation.Outcome,
			Assurance: string(res.Attestation.Assurance),
			CacheHit:  res.CacheHit,
		}
	}

	var results []verifyResult
	exitCode := 0

	if *projectFlag {
		maxWorkers := *parallelFlag
		if maxWorkers <= 0 {
			maxWorkers = runtime.NumCPU()
		}

		attestations := loadAttestations(root, useJSON)
		levels := g.Levels()

		for _, level := range levels {
			var open []string
			for _, id := range level {
				att, ok := attestations[id]
				if ok && att.Outcome == string(ir.StatusAccepted) {
					continue
				}
				open = append(open, id)
			}
			if len(open) == 0 {
				continue
			}

			sem := make(chan struct{}, maxWorkers)
			var mu sync.Mutex
			var wg sync.WaitGroup
			levelResults := make([]verifyResult, len(open))

			for i, claimID := range open {
				wg.Add(1)
				go func(idx int, cid string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					res := runOne(cid)
					mu.Lock()
					levelResults[idx] = res
					mu.Unlock()
				}(i, claimID)
			}
			wg.Wait()

			sort.Slice(levelResults, func(i, j int) bool {
				return levelResults[i].ClaimID < levelResults[j].ClaimID
			})
			for _, res := range levelResults {
				if res.Error != "" || res.Outcome != "accepted" {
					exitCode = 1
				}
				if !useJSON {
					printResult(res)
				}
				results = append(results, res)
			}
		}
	} else {
		if len(fs.Args()) == 0 {
			die(useJSON, errors.CodeInvalidInput, "usage: proofctl verify @<claim-id> or --project")
		}
		claimID := strings.TrimPrefix(fs.Args()[0], "@")
		res := runOne(claimID)
		if res.Error != "" || res.Outcome != "accepted" {
			exitCode = 1
		}
		if !useJSON {
			printResult(res)
		}
		results = append(results, res)
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
