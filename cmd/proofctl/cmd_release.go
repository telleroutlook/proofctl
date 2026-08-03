package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
	"github.com/telleroutlook/proofctl/internal/release"
	"github.com/telleroutlook/proofctl/internal/runner"
	"github.com/telleroutlook/proofctl/internal/verify"
)

func cmdRelease(args []string, useJSON bool) {
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	_ = fs.String("target", "", "target claim ID (@claim-id)")
	dryRunFlag := fs.Bool("dry-run", false, "dry run (do not write STATUS.json)")
	fixFlag := fs.Bool("fix", false, "auto-fix C04 freshness blockers; report what needs manual action")
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

	// --fix: auto-repair C04 freshness blockers, report others.
	if *fixFlag {
		cmdReleaseFix(root, cfg, g, attestations, pol, rawPG, conditions, useJSON)
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

// cmdReleaseFix auto-repairs C04 freshness blockers by running check --no-cache
// on affected claims. Other blocker types are reported with guidance.
func cmdReleaseFix(
	root string,
	cfg *config.ProjectConfig,
	g interface{ Claims() []*ir.Claim },
	attestations map[string]*ir.Attestation,
	pol policy.ReleasePolicy,
	rawPG *ir.ProofGraph,
	conditions []release.ConditionResult,
	useJSON bool,
) {
	type fixResult struct {
		Blocker string `json:"blocker"`
		Action  string `json:"action"`
		Done    bool   `json:"done"`
		Note    string `json:"note,omitempty"`
	}
	var results []fixResult

	casRoot := filepath.Join(root, config.DirName, config.CASDir)
	attestDir := filepath.Join(root, config.DirName, config.AttestDir)
	store, storeErr := cas.New(casRoot)
	nr := &runner.NativeRunner{ProjectRoot: root}
	var pipe *verify.Pipeline
	if storeErr == nil {
		pipe = &verify.Pipeline{
			DAG:        nil, // not used directly — we call pipe.Run via loadProjectGraph DAG
			CAS:        store,
			AttestDir:  attestDir,
			Runner:     nr,
			SigningKey: loadSigningKeyIfSet(),
			TrustStore: filepath.Join(root, config.DirName, "keys"),
			NoCache:    true,
		}
	}

	// Load a full DAG for pipe.
	_, _, dag, _ := loadProjectGraph(useJSON)
	if pipe != nil {
		pipe.DAG = dag
	}

	now := time.Now().UTC().Format("2006-01-02")

	for _, cond := range conditions {
		if cond.Passed {
			continue
		}
		condID := string(cond.ID)

		switch {
		case condID == string(release.CondReplayConsistency):
			// C04: auto-fix by running check --no-cache on claims missing freshness,
			// or backfilling freshness for manual-attest claims.
			fixed := 0
			var fixNotes []string
			for _, c := range dag.Claims() {
				att, ok := attestations[c.ID]
				if !ok {
					continue
				}
				if att.StartFreshness != "" && att.EndFreshness != "" {
					continue
				}
				if c.CheckerPolicy != "" && pipe != nil {
					// Re-run checker to regenerate attestation with freshness.
					checkerID, found := findChecker(rawPG, c.CheckerPolicy)
					if !found {
						fixNotes = append(fixNotes, c.ID+": no checker found")
						continue
					}
					evidence := findEvidence(rawPG, c.Evidence)
					_, runErr := pipe.Run(context.Background(), c.ID, checkerID, evidence, "")
					if runErr != nil {
						fixNotes = append(fixNotes, c.ID+": check failed: "+runErr.Error())
					} else {
						fixed++
						fixNotes = append(fixNotes, c.ID+": freshness backfilled via check")
					}
				} else {
					// Manual-attest claim: backfill freshness directly.
					att.StartFreshness = now
					att.EndFreshness = now
					att.SelfDigest = ""
					if sd, sdErr := ir.DigestOf(att); sdErr == nil {
						att.SelfDigest = sd
					}
					attData, _ := json.MarshalIndent(att, "", "  ")
					attPath := filepath.Join(attestDir, c.ID+".json")
					if writeErr := os.WriteFile(attPath, append(attData, '\n'), 0o644); writeErr == nil {
						fixed++
						fixNotes = append(fixNotes, c.ID+": freshness backfilled (manual attest)")
					} else {
						fixNotes = append(fixNotes, c.ID+": write failed: "+writeErr.Error())
					}
				}
			}
			results = append(results, fixResult{
				Blocker: condID,
				Action:  "backfill freshness via check --no-cache",
				Done:    fixed > 0 && len(fixNotes) == len(dag.Claims()),
				Note:    strings.Join(fixNotes, "; "),
			})

		case strings.HasPrefix(condID, "meta:"):
			// Domain metadata — needs replay to populate bridge.py output.
			key := strings.TrimPrefix(condID, "meta:")
			results = append(results, fixResult{
				Blocker: condID,
				Action:  "manual",
				Done:    false,
				Note:    "meta key '" + key + "' is populated by bridge.py — run 'proofctl replay' for the affected claim",
			})

		case condID == string(release.CondAttestationSignatures):
			results = append(results, fixResult{
				Blocker: condID,
				Action:  "manual",
				Done:    false,
				Note:    "attestation signatures require signing key — run 'proofctl attest --key <keyfile> ...' or 'proofctl check' with PROOFCTL_SIGNING_KEY set",
			})

		default:
			results = append(results, fixResult{
				Blocker: condID,
				Action:  "manual",
				Done:    false,
				Note:    cond.Blocker + " — requires manual intervention",
			})
		}
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"results": results})
		return
	}

	if len(results) == 0 {
		fmt.Println("release --fix: no blockers to fix — run 'proofctl release --dry-run' to verify")
		return
	}

	autoFixed := 0
	for _, r := range results {
		icon := "MANUAL"
		if r.Done {
			icon = "FIXED "
			autoFixed++
		}
		fmt.Printf("[%s] %s\n", icon, r.Blocker)
		if r.Note != "" {
			fmt.Printf("         %s\n", r.Note)
		}
	}
	fmt.Printf("\n%d blocker(s) auto-fixed, %d require manual action\n",
		autoFixed, len(results)-autoFixed)
	if autoFixed > 0 {
		fmt.Println("Re-run 'proofctl release --dry-run' to check remaining blockers.")
	}
}
