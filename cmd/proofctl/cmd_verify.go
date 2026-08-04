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
	"github.com/telleroutlook/proofctl/internal/signing"
	"github.com/telleroutlook/proofctl/internal/verify"
)

// cmdVerify implements the verify subcommand.
//
// Usage:
//
//	proofctl verify @<claim-id>
//	proofctl verify --project [--parallel N]
//	proofctl verify --signature-only @<claim-id>
//	proofctl verify --signature-only --project
func cmdVerify(args []string, useJSON bool) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	projectFlag := fs.Bool("project", false, "verify all open claims in dependency order")
	parallelFlag := fs.Int("parallel", 0, "max parallel checkers for --project (0 = number of CPUs)")
	sigOnlyFlag := fs.Bool("signature-only", false, "verify signature + evidence digests without re-running the checker")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "verify: "+err.Error())
	}

	if *sigOnlyFlag {
		cmdVerifySignatureOnly(fs.Args(), *projectFlag, useJSON)
		return
	}

	root, _, g, _ := loadProjectGraph(useJSON)

	casRoot := filepath.Join(root, config.DirName, config.CASDir)
	store, err := cas.New(casRoot)
	if err != nil {
		die(useJSON, errors.CodeInternalError, fmt.Sprintf("cannot open CAS at %s: %v", casRoot, err))
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
		// Warn on dependency manifest drift before running the checker.
		if warn := checkDependencyDrift(root, checkerID); warn != "" {
			fmt.Fprintln(os.Stderr, "warn:", warn)
		}
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

	// runBatchGroup invokes the checker once for all claims in a BatchGroup and
	// writes one attestation per claim. All claims in the group share the same checker.
	runBatchGroup := func(groupClaims []*ir.Claim) []verifyResult {
		if len(groupClaims) == 0 {
			return nil
		}
		pg := loadRawGraph(root, useJSON)
		checkerID, found := findChecker(pg, groupClaims[0].CheckerPolicy)
		if !found {
			out := make([]verifyResult, len(groupClaims))
			for i, c := range groupClaims {
				out[i] = verifyResult{ClaimID: c.ID, Outcome: "error", Error: "no checker for policy " + c.CheckerPolicy}
			}
			return out
		}
		if warn := checkDependencyDrift(root, checkerID); warn != "" {
			fmt.Fprintln(os.Stderr, "warn:", warn)
		}
		// Build batch input using the first claim's evidence (group shares evidence).
		evidence := findEvidence(pg, groupClaims[0].Evidence)
		nr, ok := pipe.Runner.(*runner.NativeRunner)
		if !ok {
			// Fallback: run individually.
			out := make([]verifyResult, len(groupClaims))
			for i, c := range groupClaims {
				out[i] = runOne(c.ID)
			}
			return out
		}
		inputJSON, _ := json.Marshal(map[string]any{
			"protocol_version": 2,
			"claim_ids": func() []string {
				ids := make([]string, len(groupClaims))
				for i, c := range groupClaims {
					ids[i] = c.ID
				}
				return ids
			}(),
			"evidence": evidence,
		})
		claimResults, batchErr := nr.RunBatch(context.Background(), checkerID, strings.NewReader(string(inputJSON)))
		if batchErr != nil {
			out := make([]verifyResult, len(groupClaims))
			for i, c := range groupClaims {
				out[i] = verifyResult{ClaimID: c.ID, Outcome: "error", Error: batchErr.Error()}
			}
			return out
		}
		// Map results by claim ID; write attestations.
		resultByID := make(map[string]verifyResult, len(claimResults))
		attestDir := filepath.Join(root, config.DirName, config.AttestDir)
		if mkErr := os.MkdirAll(attestDir, 0o755); mkErr != nil {
			out := make([]verifyResult, len(groupClaims))
			for i, c := range groupClaims {
				out[i] = verifyResult{ClaimID: c.ID, Outcome: "error",
					Error: fmt.Sprintf("cannot create attestation dir %s: %v", attestDir, mkErr)}
			}
			return out
		}
		for _, cr := range claimResults {
			allPass := len(cr.ObligationResults) > 0
			for _, r := range cr.ObligationResults {
				if r.Verdict != "pass" {
					allPass = false
					break
				}
			}
			outcome := "rejected"
			if allPass {
				outcome = "accepted"
			}
			att := &ir.Attestation{
				ClaimID:   cr.ClaimID,
				Outcome:   outcome,
				Assurance: "", // v2: proofverify derives assurance
				Toolchain: cr.Toolchain,
			}
			data, marshalErr := json.MarshalIndent(att, "", "  ")
			if marshalErr != nil {
				resultByID[cr.ClaimID] = verifyResult{ClaimID: cr.ClaimID, Outcome: "error",
					Error: fmt.Sprintf("marshal attestation for %s: %v", cr.ClaimID, marshalErr)}
				continue
			}
			attPath := filepath.Join(attestDir, cr.ClaimID+".json")
			if writeErr := os.WriteFile(attPath, append(data, '\n'), 0o644); writeErr != nil {
				resultByID[cr.ClaimID] = verifyResult{ClaimID: cr.ClaimID, Outcome: "error",
					Error: fmt.Sprintf("write attestation %s: %v", attPath, writeErr)}
				continue
			}
			resultByID[cr.ClaimID] = verifyResult{
				ClaimID: cr.ClaimID,
				Outcome: outcome,
			}
		}
		out := make([]verifyResult, len(groupClaims))
		for i, c := range groupClaims {
			if r, ok := resultByID[c.ID]; ok {
				out[i] = r
			} else {
				out[i] = verifyResult{ClaimID: c.ID, Outcome: "error", Error: "no batch result returned for claim"}
			}
		}
		return out
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

			// Split open claims into batch groups and individual claims.
			batchGroups := make(map[string][]*ir.Claim) // group → claims
			var individual []string
			for _, id := range open {
				c := g.Claim(id)
				if c != nil && c.BatchGroup != "" {
					batchGroups[c.BatchGroup] = append(batchGroups[c.BatchGroup], c)
				} else {
					individual = append(individual, id)
				}
			}

			sem := make(chan struct{}, maxWorkers)
			var mu sync.Mutex
			var wg sync.WaitGroup
			var levelResults []verifyResult

			// Dispatch individual claims concurrently.
			indivResults := make([]verifyResult, len(individual))
			for i, claimID := range individual {
				wg.Add(1)
				go func(idx int, cid string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					res := runOne(cid)
					mu.Lock()
					indivResults[idx] = res
					mu.Unlock()
				}(i, claimID)
			}
			wg.Wait()
			levelResults = append(levelResults, indivResults...)

			// Dispatch each batch group sequentially (one subprocess per group).
			for _, groupClaims := range batchGroups {
				batchResults := runBatchGroup(groupClaims)
				levelResults = append(levelResults, batchResults...)
			}

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
		arg := fs.Args()[0]
		// Accept both @<claim-id> and a path to an attestation JSON file.
		var claimID string
		if strings.HasSuffix(arg, ".json") {
			base := strings.TrimSuffix(filepath.Base(arg), ".json")
			claimID = strings.TrimPrefix(base, "@")
		} else {
			claimID = strings.TrimPrefix(arg, "@")
		}
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

// checkDependencyDrift returns a non-empty warning string if the checker's
// pinned dependency manifest digest does not match the current file on disk.
// Returns "" if no manifest was pinned or the digest matches.
func checkDependencyDrift(projectRoot string, checkerID ir.CheckerIdentity) string {
	pinned := checkerID.Runtime.DependencyManifestDigest
	relPath := checkerID.Runtime.DependencyManifestPath
	if pinned == "" || relPath == "" {
		return ""
	}
	absPath := relPath
	if !filepath.IsAbs(relPath) {
		absPath = filepath.Join(projectRoot, relPath)
	}
	current, err := hashFile(absPath)
	if err != nil {
		return fmt.Sprintf("dependency-drift: cannot hash %s: %v", relPath, err)
	}
	if current != pinned {
		return fmt.Sprintf("dependency-drift: %s has changed since pinning (pinned=%s current=%s) — run 'proofctl pin checker --lock %s' to update",
			relPath, pinned[:16]+"…", current[:16]+"…", relPath)
	}
	return ""
}

// loadSigningKeyIfSet loads the private key from PROOFCTL_SIGNING_KEY env var,
// or from .proofctl/keys/default.priv if the env var is not set.
// Returns nil (no signing) if neither exists.
func loadSigningKeyIfSet() *signing.Key {
	path := os.Getenv("PROOFCTL_SIGNING_KEY")
	if path == "" {
		return nil
	}
	k, err := signing.LoadPrivate(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: cannot load signing key %s: %v\n", path, err)
		return nil
	}
	return k
}

// loadSigningKeyFromPath loads a private signing key from an explicit path.
func loadSigningKeyFromPath(path string) (*signing.Key, error) {
	return signing.LoadPrivate(path)
}

// cmdVerifySignatureOnly verifies attestation signatures and evidence digests
// without re-running the checker. For each attestation it checks:
//  1. self_digest matches sha256(attestation-sans-self_digest)
//  2. signature is valid against a key in the trust store (if signed)
//  3. all evidence digests are present in CAS
func cmdVerifySignatureOnly(positional []string, projectMode bool, useJSON bool) {
	root, _, g, _ := loadProjectGraph(useJSON)

	casRoot := filepath.Join(root, config.DirName, config.CASDir)
	store, err := cas.New(casRoot)
	if err != nil {
		die(useJSON, errors.CodeInternalError, fmt.Sprintf("cannot open CAS at %s: %v", casRoot, err))
	}

	trustStore := filepath.Join(root, config.DirName, "keys")
	pipe := &verify.Pipeline{
		DAG:        g,
		CAS:        store,
		AttestDir:  filepath.Join(root, config.DirName, config.AttestDir),
		TrustStore: trustStore,
	}

	type sigResult struct {
		ClaimID string `json:"claim_id"`
		OK      bool   `json:"ok"`
		Error   string `json:"error,omitempty"`
	}

	var targets []string
	if projectMode {
		for _, c := range g.Claims() {
			targets = append(targets, c.ID)
		}
	} else {
		if len(positional) == 0 {
			die(useJSON, errors.CodeInvalidInput, "usage: proofctl verify --signature-only @<claim-id> or --project")
		}
		arg := positional[0]
		claimID := strings.TrimPrefix(strings.TrimSuffix(filepath.Base(strings.TrimSuffix(arg, ".json")), ".json"), "@")
		targets = []string{claimID}
	}

	var results []sigResult
	exitCode := 0
	for _, claimID := range targets {
		r := sigResult{ClaimID: claimID}
		if err := pipe.VerifySignatureOnly(claimID); err != nil {
			r.Error = err.Error()
			exitCode = 1
		} else {
			r.OK = true
		}
		if !useJSON {
			if r.OK {
				fmt.Printf("OK %s\n", claimID)
			} else {
				fmt.Printf("FAIL %s: %s\n", claimID, r.Error)
			}
		}
		results = append(results, r)
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
