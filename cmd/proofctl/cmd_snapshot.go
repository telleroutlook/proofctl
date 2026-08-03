package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/snapshot"
	"github.com/telleroutlook/proofctl/internal/status"
)

// cmdSnapshot implements the snapshot subcommand.
//
// Usage:
//
//	proofctl snapshot [--output-dir <dir>]
//	proofctl snapshot --diff <snapshot-a> <snapshot-b>
func cmdSnapshot(args []string, useJSON bool) {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	outputDirFlag := fs.String("output-dir", "", "directory for snapshot output (default: .proofctl/snapshots/)")
	diffFlag := fs.Bool("diff", false, "diff two snapshot files: snapshot --diff <a.snapshot.json> <b.snapshot.json>")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "snapshot: "+err.Error())
	}

	if *diffFlag {
		if fs.NArg() < 2 {
			die(useJSON, errors.CodeInvalidInput, "snapshot --diff requires two snapshot file paths")
		}
		cmdSnapshotDiff(fs.Arg(0), fs.Arg(1), useJSON)
		return
	}

	root, _, g, attestations := loadProjectGraph(useJSON)

	outputDir := *outputDirFlag
	if outputDir == "" {
		outputDir = filepath.Join(root, config.DirName, "snapshots")
	}

	statuses := status.Compute(g, attestations)

	claimPtrs := g.Claims()
	claims := make([]ir.Claim, len(claimPtrs))
	for i, c := range claimPtrs {
		claims[i] = *c
	}

	createdAt := time.Now().UTC().Format(time.RFC3339)
	snap, err := snapshot.Take(claims, attestations, statuses, createdAt)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "snapshot take: "+err.Error())
	}

	path, err := snapshot.Write(snap, outputDir)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "snapshot write: "+err.Error())
	}

	if useJSON {
		type snapshotOutput struct {
			Path      string `json:"path"`
			Digest    string `json:"digest"`
			Claims    int    `json:"claims"`
			CreatedAt string `json:"created_at"`
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(snapshotOutput{
			Path:      path,
			Digest:    snap.SelfDigest,
			Claims:    len(snap.Claims),
			CreatedAt: snap.CreatedAt,
		})
		return
	}

	fmt.Printf("Snapshot written: %s  digest: %s\n", path, snap.SelfDigest)
}

// cmdSnapshotDiff compares two snapshot files and prints what changed.
func cmdSnapshotDiff(pathA, pathB string, useJSON bool) {
	loadSnap := func(p string) *snapshot.Snapshot {
		data, err := os.ReadFile(p)
		if err != nil {
			die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("snapshot --diff: cannot read %s: %v", p, err))
		}
		var s snapshot.Snapshot
		if err := json.Unmarshal(data, &s); err != nil {
			die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("snapshot --diff: cannot parse %s: %v", p, err))
		}
		return &s
	}

	a := loadSnap(pathA)
	b := loadSnap(pathB)

	type claimDiff struct {
		ClaimID    string `json:"claim_id"`
		StatusA    string `json:"status_a"`
		StatusB    string `json:"status_b"`
		AssuranceA string `json:"assurance_a,omitempty"`
		AssuranceB string `json:"assurance_b,omitempty"`
		Changed    string `json:"changed"` // "status", "assurance", "added", "removed"
	}

	// Collect all claim IDs from both snapshots.
	allIDs := make(map[string]struct{})
	for id := range a.Statuses {
		allIDs[id] = struct{}{}
	}
	for id := range b.Statuses {
		allIDs[id] = struct{}{}
	}

	attAssurance := func(snap *snapshot.Snapshot, id string) string {
		if att, ok := snap.Attestations[id]; ok && att != nil {
			return string(att.Assurance)
		}
		return ""
	}

	var diffs []claimDiff
	for id := range allIDs {
		sA, inA := a.Statuses[id]
		sB, inB := b.Statuses[id]
		assA := attAssurance(a, id)
		assB := attAssurance(b, id)

		switch {
		case !inA && inB:
			diffs = append(diffs, claimDiff{ClaimID: id, StatusA: "(absent)", StatusB: sB, AssuranceB: assB, Changed: "added"})
		case inA && !inB:
			diffs = append(diffs, claimDiff{ClaimID: id, StatusA: sA, StatusB: "(removed)", AssuranceA: assA, Changed: "removed"})
		case sA != sB:
			diffs = append(diffs, claimDiff{ClaimID: id, StatusA: sA, StatusB: sB, AssuranceA: assA, AssuranceB: assB, Changed: "status"})
		case assA != assB:
			diffs = append(diffs, claimDiff{ClaimID: id, StatusA: sA, StatusB: sB, AssuranceA: assA, AssuranceB: assB, Changed: "assurance"})
		}
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"snapshot_a":    pathA,
			"snapshot_b":    pathB,
			"created_at_a":  a.CreatedAt,
			"created_at_b":  b.CreatedAt,
			"changed_count": len(diffs),
			"changes":       diffs,
		})
		return
	}

	fmt.Printf("Snapshot diff\n")
	fmt.Printf("  A: %s  (%s)\n", pathA, a.CreatedAt)
	fmt.Printf("  B: %s  (%s)\n\n", pathB, b.CreatedAt)

	if len(diffs) == 0 {
		fmt.Println("No changes between snapshots.")
		return
	}

	fmt.Printf("%-42s  %-12s  %-12s  %s\n", "CLAIM", "STATUS A", "STATUS B", "CHANGE")
	fmt.Printf("%-42s  %-12s  %-12s  %s\n", strings.Repeat("-", 42), strings.Repeat("-", 12), strings.Repeat("-", 12), strings.Repeat("-", 20))
	for _, d := range diffs {
		detail := ""
		if d.Changed == "assurance" {
			detail = fmt.Sprintf("assurance: %s → %s", d.AssuranceA, d.AssuranceB)
		} else if d.AssuranceB != "" && d.Changed == "status" {
			detail = "assurance: " + d.AssuranceB
		}
		fmt.Printf("%-42s  %-12s  %-12s  %s\n", d.ClaimID, d.StatusA, d.StatusB, detail)
	}
	fmt.Printf("\n%d change(s) total\n", len(diffs))
}
