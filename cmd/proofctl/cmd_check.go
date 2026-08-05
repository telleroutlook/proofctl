package main

// cmdCheck implements the check subcommand.
//
// check runs the checker against already-imported CAS evidence for one claim,
// without re-running the generator. It is the lightweight counterpart to replay:
// use check when evidence is already in CAS and you only want to re-verify the
// checker's verdict.
//
// Usage:
//
//	proofctl check @<claim-id>
//	proofctl check --claim <claim-id>
//	proofctl check --all [--no-cache]

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/runner"
	"github.com/telleroutlook/proofctl/internal/verify"
)

func cmdCheck(args []string, useJSON bool) {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	claimFlag := fs.String("claim", "", "claim ID to check (alternative to @<claim-id> positional arg)")
	noCacheFlag := fs.Bool("no-cache", false, "skip cache lookup and re-run checker unconditionally")
	allFlag := fs.Bool("all", false, "check all claims that have a checker_policy and CAS evidence")
	evidenceFlag := fs.String("evidence", "", "only run checker for this specific evidence digest (single-evidence override)")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "check: "+err.Error())
	}

	root, _, g, _ := loadProjectGraph(useJSON)
	pg := loadRawGraph(root, useJSON)

	casRoot := filepath.Join(root, config.DirName, config.CASDir)
	store, err := cas.New(casRoot)
	if err != nil {
		die(useJSON, errors.CodeInternalError, fmt.Sprintf("check: cannot open CAS at %s: %v", casRoot, err))
	}

	attestDir := filepath.Join(root, config.DirName, config.AttestDir)
	nr := &runner.NativeRunner{ProjectRoot: root}
	pipe := &verify.Pipeline{
		DAG:         g,
		CAS:         store,
		AttestDir:   attestDir,
		Runner:      nr,
		SigningKey:  loadSigningKeyIfSet(),
		TrustStore:  filepath.Join(root, config.DirName, "keys"),
		NoCache:     *noCacheFlag,
		ProjectRoot: root,
	}

	if *allFlag {
		cmdCheckAll(pipe, g, pg, root, useJSON)
		return
	}

	claimID := *claimFlag
	if claimID == "" && fs.NArg() >= 1 {
		claimID = strings.TrimPrefix(fs.Arg(0), "@")
	}
	if claimID == "" {
		die(useJSON, errors.CodeInvalidInput, "check: provide a claim ID via @<id>, --claim <id>, or --all")
	}

	claim := g.Claim(claimID)
	if claim == nil {
		die(useJSON, errors.CodeMissingDependency, fmt.Sprintf("check: unknown claim %q", claimID))
	}
	if claim.CheckerPolicy == "" {
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("check: claim %q has no checker_policy — cannot run check (use 'proofctl attest' to record manual review)", claimID))
	}

	checkerID, found := findChecker(pg, claim.CheckerPolicy)
	if !found {
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("check: no checker found for policy %q", claim.CheckerPolicy))
	}
	evidence := findEvidence(pg, claim.Evidence)
	if *evidenceFlag != "" {
		filtered := make([]ir.EvidenceDescriptor, 0, 1)
		for _, ev := range evidence {
			if ev.Digest == *evidenceFlag {
				filtered = append(filtered, ev)
			}
		}
		if len(filtered) == 0 {
			die(useJSON, errors.CodeMissingEvidence, fmt.Sprintf("check: digest %q not found in evidence for claim %q", *evidenceFlag, claimID))
		}
		evidence = filtered
	}

	if warn := checkDependencyDrift(root, checkerID); warn != "" {
		fmt.Fprintln(os.Stderr, "warn:", warn)
	}

	res, runErr := pipe.Run(context.Background(), claimID, checkerID, evidence, "")

	if useJSON {
		type checkOutput struct {
			ClaimID   string `json:"claim_id"`
			Outcome   string `json:"outcome"`
			Assurance string `json:"assurance,omitempty"`
			CacheHit  bool   `json:"cache_hit"`
			Error     string `json:"error,omitempty"`
		}
		out := checkOutput{ClaimID: claimID}
		if runErr != nil {
			out.Outcome = "error"
			out.Error = runErr.Error()
		} else {
			out.Outcome = res.Attestation.Outcome
			out.Assurance = string(res.Attestation.Assurance)
			out.CacheHit = res.CacheHit
		}
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(out)
		if runErr != nil || out.Outcome != "accepted" {
			os.Exit(1)
		}
		return
	}

	if runErr != nil {
		fmt.Fprintf(os.Stderr, "ERROR %s: %v\n", claimID, runErr)
		os.Exit(1)
	}
	cacheNote := ""
	if res.CacheHit {
		keyHint := res.CacheKey
		if len(keyHint) > 12 {
			keyHint = keyHint[:12] + "..."
		}
		cacheNote = " [cache-hit key=" + keyHint + "; invalidate: proofctl cache invalidate " + claimID + "]"
	}
	if res.Attestation.Outcome == "accepted" {
		fmt.Printf("PASS %s%s\n", claimID, cacheNote)
	} else {
		fmt.Printf("FAIL %s: outcome=%s%s\n", claimID, res.Attestation.Outcome, cacheNote)
		os.Exit(1)
	}
}

// cmdCheckAll runs checkers for every claim that has a checker_policy, logging
// a pytest-style summary at the end.
func cmdCheckAll(pipe *verify.Pipeline, g interface {
	Claims() []*ir.Claim
}, pg *ir.ProofGraph, root string, useJSON bool) {
	type checkResult struct {
		ClaimID   string `json:"claim_id"`
		Outcome   string `json:"outcome"`
		Assurance string `json:"assurance,omitempty"`
		CacheHit  bool   `json:"cache_hit"`
		Skipped   bool   `json:"skipped,omitempty"`
		SkipNote  string `json:"skip_note,omitempty"`
		Error     string `json:"error,omitempty"`
	}

	claims := g.Claims()
	results := make([]checkResult, 0, len(claims))
	passed, failed, skipped := 0, 0, 0

	for _, claim := range claims {
		if claim.CheckerPolicy == "" {
			results = append(results, checkResult{
				ClaimID:  claim.ID,
				Skipped:  true,
				SkipNote: "no checker_policy",
			})
			skipped++
			continue
		}

		checkerID, found := findChecker(pg, claim.CheckerPolicy)
		if !found {
			results = append(results, checkResult{
				ClaimID:  claim.ID,
				Skipped:  true,
				SkipNote: fmt.Sprintf("no checker for policy %q", claim.CheckerPolicy),
			})
			skipped++
			continue
		}

		evidence := findEvidence(pg, claim.Evidence)
		res, runErr := pipe.Run(context.Background(), claim.ID, checkerID, evidence, "")

		r := checkResult{ClaimID: claim.ID}
		if runErr != nil {
			r.Outcome = "error"
			r.Error = runErr.Error()
			failed++
		} else {
			r.Outcome = res.Attestation.Outcome
			r.Assurance = string(res.Attestation.Assurance)
			r.CacheHit = res.CacheHit
			if res.Attestation.Outcome == "accepted" {
				passed++
			} else {
				failed++
			}
		}
		results = append(results, r)
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"results": results,
			"summary": map[string]int{"passed": passed, "failed": failed, "skipped": skipped},
		})
		if failed > 0 {
			os.Exit(1)
		}
		return
	}

	// Pytest-style output.
	for _, r := range results {
		switch {
		case r.Skipped:
			fmt.Printf("SKIP  %-40s %s\n", r.ClaimID, r.SkipNote)
		case r.Error != "":
			fmt.Printf("ERROR %-40s %s\n", r.ClaimID, r.Error)
		case r.Outcome == "accepted":
			cacheNote := ""
			if r.CacheHit {
				cacheNote = " [cache-hit]"
			}
			fmt.Printf("PASS  %-40s%s\n", r.ClaimID, cacheNote)
		default:
			fmt.Printf("FAIL  %-40s outcome=%s\n", r.ClaimID, r.Outcome)
		}
	}

	total := passed + failed
	fmt.Printf("\n%d passed, %d failed, %d skipped", passed, failed, skipped)
	if total > 0 {
		fmt.Printf(" out of %d checked", total)
	}
	fmt.Println()

	if failed > 0 {
		os.Exit(1)
	}
}
