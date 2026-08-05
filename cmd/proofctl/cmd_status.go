package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/telleroutlook/proofctl/internal/config"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/status"
)

const zeroDigestPrefix = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

func cmdStatus(args []string, useJSON bool) {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	verboseFlag := fs.Bool("verbose", false, "show toolchain info for accepted claims")
	watchFlag := fs.Bool("watch", false, "re-print status whenever .proofctl/ or graph source changes (poll every 2s)")
	_ = fs.Parse(args)

	if *watchFlag {
		cmdStatusWatch(*verboseFlag, useJSON)
		return
	}

	printStatus(*verboseFlag, useJSON)
}

func printStatus(verbose, useJSON bool) {
	root, cfg, g, attestations := loadProjectGraph(useJSON)

	// Load policy to resolve release_target (best-effort; nil if no policy configured).
	releaseTarget := loadReleaseTargetFromPolicy(root, cfg.PolicyFile)

	statuses := status.Compute(g, attestations)

	topoOrder, topoErr := topoSort(g)
	if topoErr != nil {
		topoOrder = make([]string, 0, len(statuses))
		for id := range statuses {
			topoOrder = append(topoOrder, id)
		}
		sort.Strings(topoOrder)
	}

	// Build per-claim OPEN reason and zero-digest warnings.
	openReasons := computeOpenReasons(g, attestations)
	zeroDigestWarnings := findZeroDigestClaims(g)

	if useJSON {
		type claimStatusEntry struct {
			Status           string `json:"status"`
			Assurance        string `json:"assurance,omitempty"`
			StartFreshness   string `json:"start_freshness,omitempty"`
			EndFreshness     string `json:"end_freshness,omitempty"`
			EvidenceCount    int    `json:"evidence_count,omitempty"`
			OpenReason       string `json:"open_reason,omitempty"`
			BlockReason      string `json:"block_reason,omitempty"`
			UnverifiedDigest bool   `json:"unverified_digest,omitempty"`
		}
		claimsMap := make(map[string]claimStatusEntry, len(statuses))
		for id, s := range statuses {
			entry := claimStatusEntry{Status: string(s)}
			if att, ok := attestations[id]; ok {
				if att.BlockReason != "" {
					entry.BlockReason = att.BlockReason
				}
				entry.Assurance = string(att.Assurance)
				entry.StartFreshness = att.StartFreshness
				entry.EndFreshness = att.EndFreshness
				entry.EvidenceCount = len(att.Evidence)
			}
			if s == ir.StatusOpen {
				entry.OpenReason = openReasons[id]
			}
			if zeroDigestWarnings[id] {
				entry.UnverifiedDigest = true
			}
			claimsMap[id] = entry
		}
		type summaryEntry struct {
			Accepted int `json:"accepted"`
			Blocked  int `json:"blocked"`
			Open     int `json:"open"`
			Rejected int `json:"rejected"`
		}
		var summ summaryEntry
		for _, s := range statuses {
			switch s {
			case ir.StatusAccepted:
				summ.Accepted++
			case ir.StatusBlocked:
				summ.Blocked++
			case ir.StatusOpen:
				summ.Open++
			case ir.StatusRejected:
				summ.Rejected++
			}
		}
		type statusOutput struct {
			Claims            map[string]claimStatusEntry `json:"claims"`
			Summary           summaryEntry                `json:"summary"`
			ReleaseTarget     any                         `json:"release_target"`
			UnverifiedDigests []string                    `json:"unverified_digests,omitempty"`
		}
		var unverified []string
		for id := range zeroDigestWarnings {
			unverified = append(unverified, id)
		}
		sort.Strings(unverified)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(statusOutput{
			Claims:            claimsMap,
			Summary:           summ,
			ReleaseTarget:     releaseTarget,
			UnverifiedDigests: unverified,
		})
		return
	}

	fmt.Println("Proof Graph Status")
	fmt.Println("==================")

	var accepted, open, blocked, rejected int
	for _, id := range topoOrder {
		s := statuses[id]
		switch s {
		case ir.StatusAccepted:
			accepted++
		case ir.StatusOpen:
			open++
		case ir.StatusBlocked:
			blocked++
		case ir.StatusRejected:
			rejected++
		}

		annotation := ""
		if att, ok := attestations[id]; ok && att.BlockReason != "" {
			annotation = "  " + att.BlockReason
		} else if s == ir.StatusOpen {
			annotation = "  (" + openReasons[id] + ")"
		}
		unverifiedMark := ""
		if zeroDigestWarnings[id] {
			unverifiedMark = " [UNVERIFIED_DIGEST]"
		}
		fmt.Printf("%-40s %-10s%s%s\n", id, strings.ToUpper(string(s)), unverifiedMark, annotation)
		if verbose && s == ir.StatusAccepted {
			if att, ok := attestations[id]; ok && len(att.Toolchain) > 0 {
				keys := make([]string, 0, len(att.Toolchain))
				for k := range att.Toolchain {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					fmt.Printf("  %-38s %s=%s\n", "", k, att.Toolchain[k])
				}
			}
		}
	}
	fmt.Printf("\nSummary: %d accepted, %d blocked, %d open, %d rejected\n",
		accepted, blocked, open, rejected)
	if releaseTarget != nil {
		fmt.Printf("release_target: %s\n", *releaseTarget)
	} else {
		fmt.Println("release_target: (not configured — set policy_file in .proofctl/config.json)")
	}

	if len(zeroDigestWarnings) > 0 {
		ids := make([]string, 0, len(zeroDigestWarnings))
		for id := range zeroDigestWarnings {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		fmt.Printf("\nWARNING: %d claim(s) have zero/placeholder statement digest [UNVERIFIED_DIGEST]:\n", len(ids))
		for _, id := range ids {
			fmt.Printf("  %s — run 'proofctl compile --fix-digests' to resolve\n", id)
		}
	}
}

// computeOpenReasons returns a human-readable open reason for each OPEN claim.
// Distinguishes between "no attestation" and "no evidence registered".
func computeOpenReasons(g interface {
	Claims() []*ir.Claim
}, attestations map[string]*ir.Attestation) map[string]string {
	reasons := make(map[string]string)
	for _, c := range g.Claims() {
		if _, hasAtt := attestations[c.ID]; hasAtt {
			continue
		}
		if len(c.Evidence) == 0 {
			reasons[c.ID] = "no evidence registered"
		} else {
			reasons[c.ID] = "no attestation"
		}
	}
	return reasons
}

// findZeroDigestClaims returns the set of claim IDs whose statement.digest is zero/empty.
func findZeroDigestClaims(g interface {
	Claims() []*ir.Claim
}) map[string]bool {
	result := make(map[string]bool)
	for _, c := range g.Claims() {
		d := c.Statement.Digest
		if d == "" || d == zeroDigestPrefix {
			result[c.ID] = true
		}
	}
	return result
}

// loadReleaseTargetFromPolicy reads the policy file and returns the target claim ID,
// or nil if the policy cannot be loaded or has no target.
func loadReleaseTargetFromPolicy(root, policyFile string) *string {
	if policyFile == "" {
		return nil
	}
	polPath := filepath.Join(root, policyFile)
	data, err := os.ReadFile(polPath)
	if err != nil {
		return nil
	}
	var pol struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(data, &pol); err != nil || pol.Target == "" {
		return nil
	}
	return &pol.Target
}

// cmdStatusWatch polls .proofctl/ and the graph source every 2 seconds and
// re-prints status whenever the directory mtime changes.
func cmdStatusWatch(verbose, useJSON bool) {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "watch: cannot determine working directory:", err)
		os.Exit(1)
	}
	root, cfgErr := findProjectRoot(cwd)
	if cfgErr != nil {
		fmt.Fprintln(os.Stderr, "watch: no .proofctl found")
		os.Exit(1)
	}

	proofctlDir := filepath.Join(root, config.DirName)
	watched := []string{
		proofctlDir,
		filepath.Join(proofctlDir, config.AttestDir),
	}

	// Try to add the graph source file.
	if cfg, loadErr := config.Load(root); loadErr == nil && cfg.GraphSource != "" {
		watched = append(watched, filepath.Join(root, config.DirName, cfg.GraphSource))
	}

	lastSig := watchSignature(watched)

	if !useJSON {
		fmt.Fprintf(os.Stderr, "Watching for changes (Ctrl-C to stop)...\n\n")
	}
	printStatus(verbose, useJSON)

	for {
		time.Sleep(2 * time.Second)
		sig := watchSignature(watched)
		if sig != lastSig {
			lastSig = sig
			if !useJSON {
				fmt.Println("\n--- refresh ---")
			}
			printStatus(verbose, useJSON)
		}
	}
}

// watchSignature returns a string encoding the combined mtime+size of all
// watched paths. A change in this string means something relevant changed.
func watchSignature(paths []string) string {
	var sb strings.Builder
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(&sb, "%s:err\n", p)
			continue
		}
		fmt.Fprintf(&sb, "%s:%d:%d\n", p, info.ModTime().UnixNano(), info.Size())
	}
	return sb.String()
}
