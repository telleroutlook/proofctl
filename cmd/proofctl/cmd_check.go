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
	"github.com/telleroutlook/proofctl/internal/runner"
	"github.com/telleroutlook/proofctl/internal/verify"
)

func cmdCheck(args []string, useJSON bool) {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	claimFlag := fs.String("claim", "", "claim ID to check (alternative to @<claim-id> positional arg)")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "check: "+err.Error())
	}

	claimID := *claimFlag
	if claimID == "" && fs.NArg() >= 1 {
		claimID = strings.TrimPrefix(fs.Arg(0), "@")
	}
	if claimID == "" {
		die(useJSON, errors.CodeInvalidInput, "check: provide a claim ID via @<id> or --claim <id>")
	}

	root, _, g, _ := loadProjectGraph(useJSON)

	claim := g.Claim(claimID)
	if claim == nil {
		die(useJSON, errors.CodeMissingDependency, fmt.Sprintf("check: unknown claim %q", claimID))
	}
	if claim.CheckerPolicy == "" {
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("check: claim %q has no checker_policy — cannot run check (use 'proofctl attest' to record manual review)", claimID))
	}

	pg := loadRawGraph(root, useJSON)
	checkerID, found := findChecker(pg, claim.CheckerPolicy)
	if !found {
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("check: no checker found for policy %q", claim.CheckerPolicy))
	}
	evidence := findEvidence(pg, claim.Evidence)

	if warn := checkDependencyDrift(root, checkerID); warn != "" {
		fmt.Fprintln(os.Stderr, "warn:", warn)
	}

	casRoot := filepath.Join(root, config.DirName, config.CASDir)
	store, err := cas.New(casRoot)
	if err != nil {
		die(useJSON, errors.CodeInternalError, fmt.Sprintf("check: cannot open CAS at %s: %v", casRoot, err))
	}

	attestDir := filepath.Join(root, config.DirName, config.AttestDir)
	nr := &runner.NativeRunner{ProjectRoot: root}
	pipe := &verify.Pipeline{
		DAG:        g,
		CAS:        store,
		AttestDir:  attestDir,
		Runner:     nr,
		SigningKey: loadSigningKeyIfSet(),
		TrustStore: filepath.Join(root, config.DirName, "keys"),
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
		cacheNote = " [cache-hit]"
	}
	if res.Attestation.Outcome == "accepted" {
		fmt.Printf("PASS %s%s\n", claimID, cacheNote)
	} else {
		fmt.Printf("FAIL %s: outcome=%s%s\n", claimID, res.Attestation.Outcome, cacheNote)
		os.Exit(1)
	}
}
