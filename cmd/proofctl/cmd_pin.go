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
	schemaFlag := fs.String("schema", "", "JSON Schema file to pin (computes schema_digest and records schema_path)")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}
	if *cmdFlag == "" {
		die(useJSON, errors.CodeInvalidInput, "pin checker: --cmd is required")
	}

	root, cfg, _, _ := loadProjectGraph(useJSON)

	// Load raw graph source (not compiled DAG) so we can rewrite it.
	srcPath := filepath.Join(root, config.DirName, cfg.GraphSource)
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

	// Reject absolute paths in cmd[1:] that are not ${VAR} placeholders.
	// Absolute paths break portability across machines; use relative paths or ${ENV_VAR}.
	for i, part := range cmdParts[1:] {
		if !strings.HasPrefix(part, "${") && !strings.HasPrefix(part, "-") && filepath.IsAbs(part) {
			die(useJSON, errors.CodeInvalidInput, fmt.Sprintf(
				"pin checker: cmd[%d] %q is an absolute path — use a relative path or ${ENV_VAR} placeholder for portability",
				i+1, part))
		}
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

	// Hash schema file if provided.
	var schemaDigest, schemaRelPath string
	if *schemaFlag != "" {
		schemaDigest, err = hashFile(*schemaFlag)
		if err != nil {
			die(useJSON, errors.CodeInternalError, "pin checker: hash schema: "+err.Error())
		}
		if rel, relErr := filepath.Rel(root, *schemaFlag); relErr == nil && !strings.HasPrefix(rel, "..") {
			schemaRelPath = rel
		} else {
			schemaRelPath = *schemaFlag
		}
	}

	// Update matching checker in the ProofGraph.
	updated := false
	for i, ch := range pg.Checkers {
		if ch.ID != targetID {
			continue
		}
		pg.Checkers[i].CheckerDigest = digest
		if schemaDigest != "" {
			pg.Checkers[i].SchemaDigest = schemaDigest
		}
		pg.Checkers[i].Runtime = ir.Runtime{
			Kind:                     "native",
			Cmd:                      cmdParts,
			SchemaPath:               schemaRelPath,
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
		fmt.Fprintln(os.Stderr, "warn: checker dependencies not pinned")
		fmt.Fprintln(os.Stderr, "  To pin, rerun with --lock pointing to your dependency manifest:")
		fmt.Fprintln(os.Stderr, "    requirements.txt   proofctl pin checker --cmd ... --lock requirements.txt")
		fmt.Fprintln(os.Stderr, "    uv.lock            proofctl pin checker --cmd ... --lock uv.lock")
		fmt.Fprintln(os.Stderr, "    go.sum             proofctl pin checker --cmd ... --lock go.sum")
	}
	// Warn if no schema was pinned.
	if schemaDigest == "" && !useJSON {
		fmt.Fprintln(os.Stderr, "warn: schema_digest not pinned — schema tampering will not be detected at runtime")
		fmt.Fprintln(os.Stderr, "  To pin, rerun with --schema pointing to the checker's JSON Schema file:")
		fmt.Fprintln(os.Stderr, "    proofctl pin checker --cmd ... --schema schemas/checker.schema.json")
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
			out["warn_lock"] = "checker dependencies not pinned — rerun with --lock <manifest>; accepted formats: requirements.txt, uv.lock, go.sum"
		}
		if schemaDigest != "" {
			out["schema_digest"] = schemaDigest
			out["schema_path"] = schemaRelPath
		} else {
			out["warn_schema"] = "schema_digest not pinned — rerun with --schema <schema-file>"
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
		if schemaDigest != "" {
			fmt.Printf("  schema: %s (%s)\n", schemaRelPath, schemaDigest)
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
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
