package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/telleroutlook/proofctl/internal/compile"
	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
)

func cmdPin(args []string, useJSON bool) {
	if len(args) == 0 || args[0] != "checker" {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl pin checker --cmd <command> [--id <checker-id>] [--lock <lockfile>]")
	}
	cmdPinChecker(args[1:], useJSON)
}

func cmdPinChecker(args []string, useJSON bool) {
	fs := flag.NewFlagSet("pin checker", flag.ContinueOnError)
	cmdFlag := fs.String("cmd", "", `checker command, e.g. "python3 adapters/cap/bridge.py"`)
	idFlag := fs.String("id", "", "checker ID in graph.json to update (default: first checker)")
	lockFlag := fs.String("lock", "", "dependency lockfile to pin (e.g. requirements.txt, go.sum, uv.lock)")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}
	if *cmdFlag == "" {
		die(useJSON, errors.CodeInvalidInput, "pin checker: --cmd is required")
	}

	root, cfg, _, _ := loadProjectGraph(useJSON)

	// Load raw graph source (not compiled DAG) so we can rewrite it.
	srcPath := filepath.Join(root, cfg.GraphSource)
	srcData, err := os.ReadFile(srcPath)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "pin checker: read graph source: "+err.Error())
	}
	pg, err := compile.Compile(srcData, compile.FormatJSON)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, "pin checker: parse graph: "+err.Error())
	}

	if len(pg.Checkers) == 0 {
		die(useJSON, errors.CodeInvalidInput, "pin checker: graph has no checkers")
	}

	// Find target checker.
	targetID := *idFlag
	if targetID == "" {
		targetID = pg.Checkers[0].ID
	}

	cmdParts := strings.Fields(*cmdFlag)
	if len(cmdParts) == 0 {
		die(useJSON, errors.CodeInvalidInput, "pin checker: empty command")
	}

	// Hash the last element of cmd (the script to be pinned).
	scriptPath := cmdParts[len(cmdParts)-1]
	digest, err := hashFile(scriptPath)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "pin checker: hash script: "+err.Error())
	}

	// Hash lockfile if provided.
	var lockDigest, lockRelPath string
	if *lockFlag != "" {
		lockDigest, err = hashFile(*lockFlag)
		if err != nil {
			die(useJSON, errors.CodeInternalError, "pin checker: hash lockfile: "+err.Error())
		}
		// Store path relative to project root when possible.
		if rel, relErr := filepath.Rel(root, *lockFlag); relErr == nil && !strings.HasPrefix(rel, "..") {
			lockRelPath = rel
		} else {
			lockRelPath = *lockFlag
		}
	}

	// Update matching checker in the ProofGraph.
	updated := false
	for i, ch := range pg.Checkers {
		if ch.ID != targetID {
			continue
		}
		pg.Checkers[i].CheckerDigest = digest
		pg.Checkers[i].Runtime = ir.Runtime{
			Kind:                     "native",
			Cmd:                      cmdParts,
			DependencyManifestDigest: lockDigest,
			DependencyManifestPath:   lockRelPath,
		}
		updated = true
		break
	}
	if !updated {
		available := make([]string, len(pg.Checkers))
		for i, ch := range pg.Checkers {
			available[i] = ch.ID
		}
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf(
			"pin checker: checker %q not found in graph (available: %s)",
			targetID, strings.Join(available, ", ")))
	}

	// Write back to graph source.
	data, _ := json.MarshalIndent(pg, "", "  ")
	data = append(data, '\n')
	if err := os.WriteFile(srcPath, data, 0o644); err != nil {
		die(useJSON, errors.CodeInternalError, "pin checker: write graph: "+err.Error())
	}

	// Also recompile to .proofctl/graph.json.
	graphOut := filepath.Join(root, config.DirName, config.GraphFile)
	if err := os.WriteFile(graphOut, data, 0o644); err != nil {
		die(useJSON, errors.CodeInternalError, "pin checker: write compiled graph: "+err.Error())
	}

	// Warn if no lockfile was pinned.
	if lockDigest == "" && !useJSON {
		fmt.Fprintln(os.Stderr, "warn: checker dependencies not pinned — run 'proofctl pin checker --lock <lockfile>' to pin dependency manifest")
	}

	if useJSON {
		out := map[string]string{
			"checker_id":     targetID,
			"checker_digest": digest,
			"cmd":            *cmdFlag,
			"updated":        srcPath,
		}
		if lockDigest != "" {
			out["dependency_manifest_digest"] = lockDigest
			out["dependency_manifest_path"] = lockRelPath
		} else {
			out["warn"] = "checker dependencies not pinned — run with --lock <lockfile>"
		}
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(out)
	} else {
		fmt.Printf("Pinned checker %q\n", targetID)
		fmt.Printf("  digest: %s\n", digest)
		fmt.Printf("  cmd:    %s\n", *cmdFlag)
		if lockDigest != "" {
			fmt.Printf("  lock:   %s (%s)\n", lockRelPath, lockDigest)
		}
		fmt.Printf("  written to %s\n", srcPath)
	}
}

// hashFile computes the sha256 digest of a file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
