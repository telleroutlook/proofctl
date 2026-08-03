package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
func cmdSnapshot(args []string, useJSON bool) {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	outputDirFlag := fs.String("output-dir", "", "directory for snapshot output (default: .proofctl/snapshots/)")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "snapshot: "+err.Error())
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
