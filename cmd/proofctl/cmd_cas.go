package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/compile"
	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
)

func cmdCas(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl cas <import|import-dir|list|gc> ...")
	}
	switch args[0] {
	case "import":
		cmdCasImport(args[1:], useJSON)
	case "import-dir":
		cmdCasImportDir(args[1:], useJSON)
	case "list":
		cmdCasList(args[1:], useJSON)
	case "gc":
		cmdCasGC(args[1:], useJSON)
	default:
		die(useJSON, errors.CodeInvalidInput, "unknown cas subcommand "+args[0]+"; use import, import-dir, list, or gc")
	}
}

func cmdCasImport(args []string, useJSON bool) {
	fs := flag.NewFlagSet("cas import", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}
	if fs.NArg() == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl cas import <file> [file ...]")
	}

	root, cfg, _, _ := loadProjectGraph(useJSON)

	casRoot := filepath.Join(root, config.DirName, config.CASDir)
	store, err := cas.New(casRoot)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "cannot open CAS: "+err.Error())
	}

	// Load graph source so we can update evidence sizes.
	srcPath := filepath.Join(root, cfg.GraphSource)
	srcData, err := os.ReadFile(srcPath)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "cannot read graph source: "+err.Error())
	}
	pg, err := compile.Compile(srcData, compile.FormatJSON)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, "cannot parse graph: "+err.Error())
	}

	// Build evidence index: digest → index in pg.Evidence.
	evidenceIdx := make(map[string]int, len(pg.Evidence))
	for i, ev := range pg.Evidence {
		evidenceIdx[ev.Digest] = i
	}

	type importResult struct {
		File    string `json:"file"`
		Digest  string `json:"digest"`
		Size    int64  `json:"size"`
		Updated bool   `json:"size_updated"`
		Error   string `json:"error,omitempty"`
	}
	var results []importResult

	graphModified := false
	for _, file := range fs.Args() {
		f, err := os.Open(file)
		if err != nil {
			errMsg := fmt.Sprintf("cannot open %s: %v", file, err)
			if useJSON {
				results = append(results, importResult{File: file, Error: errMsg})
			} else {
				fmt.Fprintf(os.Stderr, "cas import: %s\n", errMsg)
			}
			continue
		}
		digest, size, err := store.Store(f)
		_ = f.Close()
		if err != nil {
			errMsg := fmt.Sprintf("store %s: %v", file, err)
			if useJSON {
				results = append(results, importResult{File: file, Error: errMsg})
			} else {
				fmt.Fprintf(os.Stderr, "cas import: %s\n", errMsg)
			}
			continue
		}

		// Update evidence size in graph if this digest matches.
		// Re-verify SHA-256 when the recorded size was wrong, to catch corruption.
		updated := false
		if idx, ok := evidenceIdx[digest]; ok {
			if pg.Evidence[idx].Size != size {
				// Re-read the blob from CAS and verify its digest matches.
				desc := ir.EvidenceDescriptor{Digest: digest, Size: size}
				if verifyErr := store.Verify(desc); verifyErr != nil {
					errMsg := fmt.Sprintf("size mismatch for %s and re-verification failed: %v", file, verifyErr)
					if useJSON {
						results = append(results, importResult{File: file, Digest: digest, Size: size, Error: errMsg})
					} else {
						fmt.Fprintf(os.Stderr, "cas import: %s\n", errMsg)
					}
					continue
				}
				pg.Evidence[idx].Size = size
				graphModified = true
				updated = true
			}
		}

		results = append(results, importResult{File: file, Digest: digest, Size: size, Updated: updated})
	}

	// Write back graph source if evidence sizes changed.
	if graphModified {
		data, marshalErr := json.MarshalIndent(pg, "", "  ")
		if marshalErr != nil {
			die(useJSON, errors.CodeInternalError, "cas import: marshal graph: "+marshalErr.Error())
		}
		data = append(data, '\n')
		if err := os.WriteFile(srcPath, data, 0o644); err != nil {
			die(useJSON, errors.CodeInternalError, "cas import: write graph "+srcPath+": "+err.Error())
		}
		// Also update compiled graph.
		graphOut := filepath.Join(root, config.DirName, config.GraphFile)
		if err := os.WriteFile(graphOut, data, 0o644); err != nil {
			die(useJSON, errors.CodeInternalError, "cas import: write compiled graph "+graphOut+": "+err.Error())
		}
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	} else {
		for _, r := range results {
			if r.Error != "" {
				fmt.Printf("FAIL  %s — %s\n", r.File, r.Error)
				continue
			}
			sizeNote := ""
			if r.Updated {
				sizeNote = fmt.Sprintf(" [size updated: %d]", r.Size)
			}
			fmt.Printf("OK    %s → %s%s\n", r.File, r.Digest, sizeNote)
		}
		if graphModified {
			fmt.Printf("Updated evidence sizes in %s\n", srcPath)
		}
	}
}

func cmdCasList(args []string, useJSON bool) {
	fs := flag.NewFlagSet("cas list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	root, _, _, _ := loadProjectGraph(useJSON)
	casRoot := filepath.Join(root, config.DirName, config.CASDir)

	var blobs []string
	var walkErrors []string
	walkErr := filepath.WalkDir(filepath.Join(casRoot, "sha256"), func(path string, d iofs.DirEntry, err error) error {
		if err != nil {
			walkErrors = append(walkErrors, fmt.Sprintf("cas list: walk error at %s: %v", path, err))
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			walkErrors = append(walkErrors, fmt.Sprintf("cas list: stat error at %s: %v", path, err))
			return nil
		}
		dir := filepath.Base(filepath.Dir(path))
		file := filepath.Base(path)
		blobs = append(blobs, fmt.Sprintf("sha256:%s%s  %d", dir, file, info.Size()))
		return nil
	})
	if walkErr != nil {
		walkErrors = append(walkErrors, fmt.Sprintf("cas list: walk failed: %v", walkErr))
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(map[string]any{"blobs": blobs, "errors": walkErrors})
	} else {
		for _, e := range walkErrors {
			fmt.Fprintln(os.Stderr, "warn:", e)
		}
		if len(blobs) == 0 {
			fmt.Println("CAS is empty")
			return
		}
		for _, b := range blobs {
			fmt.Println(b)
		}
	}
}

// cmdCasImportDir imports all files in a directory matching a glob pattern.
// Usage: proofctl cas import-dir <dir> [--pattern <glob>]
func cmdCasImportDir(args []string, useJSON bool) {
	fs := flag.NewFlagSet("cas import-dir", flag.ContinueOnError)
	patternFlag := fs.String("pattern", "*", "glob pattern to filter files (e.g. '*.tex', '*.json')")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}
	if fs.NArg() == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl cas import-dir <dir> [--pattern <glob>]")
	}

	dir := fs.Arg(0)
	info, err := os.Stat(dir)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("cas import-dir: cannot stat %s: %v", dir, err))
	}
	if !info.IsDir() {
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("cas import-dir: %s is not a directory", dir))
	}

	root, cfg, _, _ := loadProjectGraph(useJSON)
	casRoot := filepath.Join(root, config.DirName, config.CASDir)
	store, err := cas.New(casRoot)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "cannot open CAS: "+err.Error())
	}

	// Load graph source for evidence size updates.
	srcPath := filepath.Join(root, cfg.GraphSource)
	srcData, err := os.ReadFile(srcPath)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "cannot read graph source: "+err.Error())
	}
	pg, err := compile.Compile(srcData, compile.FormatJSON)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, "cannot parse graph: "+err.Error())
	}
	evidenceIdx := make(map[string]int, len(pg.Evidence))
	for i, ev := range pg.Evidence {
		evidenceIdx[ev.Digest] = i
	}

	// Collect files matching pattern (non-recursive).
	entries, err := os.ReadDir(dir)
	if err != nil {
		die(useJSON, errors.CodeInternalError, fmt.Sprintf("cas import-dir: read dir %s: %v", dir, err))
	}

	type importResult struct {
		File    string `json:"file"`
		Digest  string `json:"digest,omitempty"`
		Size    int64  `json:"size,omitempty"`
		Updated bool   `json:"size_updated,omitempty"`
		Error   string `json:"error,omitempty"`
	}
	var results []importResult
	graphModified := false

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		matched, matchErr := filepath.Match(*patternFlag, entry.Name())
		if matchErr != nil {
			die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("cas import-dir: invalid pattern %q: %v", *patternFlag, matchErr))
		}
		if !matched {
			continue
		}

		filePath := filepath.Join(dir, entry.Name())
		// Use a relative path in results when possible.
		displayPath := filePath
		if rel, relErr := filepath.Rel(".", filePath); relErr == nil && !strings.HasPrefix(rel, "..") {
			displayPath = rel
		}

		f, openErr := os.Open(filePath)
		if openErr != nil {
			results = append(results, importResult{File: displayPath, Error: fmt.Sprintf("cannot open: %v", openErr)})
			continue
		}
		digest, size, storeErr := store.Store(f)
		_ = f.Close()
		if storeErr != nil {
			results = append(results, importResult{File: displayPath, Error: fmt.Sprintf("store: %v", storeErr)})
			continue
		}

		updated := false
		if idx, ok := evidenceIdx[digest]; ok && pg.Evidence[idx].Size != size {
			desc := ir.EvidenceDescriptor{Digest: digest, Size: size}
			if verifyErr := store.Verify(desc); verifyErr == nil {
				pg.Evidence[idx].Size = size
				graphModified = true
				updated = true
			}
		}
		results = append(results, importResult{File: displayPath, Digest: digest, Size: size, Updated: updated})
	}

	if graphModified {
		data, _ := json.MarshalIndent(pg, "", "  ")
		data = append(data, '\n')
		if writeErr := os.WriteFile(srcPath, data, 0o644); writeErr != nil {
			die(useJSON, errors.CodeInternalError, "cas import-dir: write graph "+srcPath+": "+writeErr.Error())
		}
		graphOut := filepath.Join(root, config.DirName, config.GraphFile)
		if writeErr := os.WriteFile(graphOut, data, 0o644); writeErr != nil {
			die(useJSON, errors.CodeInternalError, "cas import-dir: write compiled graph "+graphOut+": "+writeErr.Error())
		}
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}

	imported := 0
	for _, r := range results {
		if r.Error != "" {
			fmt.Printf("FAIL  %s — %s\n", r.File, r.Error)
		} else {
			sizeNote := ""
			if r.Updated {
				sizeNote = fmt.Sprintf(" [size updated: %d]", r.Size)
			}
			fmt.Printf("OK    %s → %s%s\n", r.File, r.Digest, sizeNote)
			imported++
		}
	}
	fmt.Printf("\n%d files imported, %d failed\n", imported, len(results)-imported)
	if graphModified {
		fmt.Printf("Updated evidence sizes in %s\n", srcPath)
	}
}

// cmdCasGC scans all attestations and graph.json to collect referenced digests,
// then deletes unreferenced blobs from the CAS and reports freed bytes.
func cmdCasGC(args []string, useJSON bool) {
	fs := flag.NewFlagSet("cas gc", flag.ContinueOnError)
	dryRunFlag := fs.Bool("dry-run", false, "report what would be deleted without deleting")
	yesFlag := fs.Bool("yes", false, "skip confirmation prompt and delete immediately")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	root, cfg, _, attestations := loadProjectGraph(useJSON)
	casRoot := filepath.Join(root, config.DirName, config.CASDir)

	// Collect all referenced digests from graph.json evidence list.
	referenced := make(map[string]struct{})
	srcPath := filepath.Join(root, cfg.GraphSource)
	if srcData, err := os.ReadFile(srcPath); err == nil {
		if pg, err := compile.Compile(srcData, compile.FormatJSON); err == nil {
			for _, ev := range pg.Evidence {
				hex := strings.TrimPrefix(ev.Digest, "sha256:")
				referenced[hex] = struct{}{}
			}
		}
	}

	// Collect digests referenced by attestations.
	for _, att := range attestations {
		for _, ev := range att.Evidence {
			hex := strings.TrimPrefix(ev.Digest, "sha256:")
			referenced[hex] = struct{}{}
		}
	}

	// Walk CAS blobs and collect candidates for deletion.
	type gcEntry struct {
		Digest  string `json:"digest"`
		Size    int64  `json:"size"`
		Deleted bool   `json:"deleted"`
		Error   string `json:"error,omitempty"`
	}
	var candidates []gcEntry
	sha256Dir := filepath.Join(casRoot, "sha256")
	prefixes, err := os.ReadDir(sha256Dir)
	if err != nil {
		if os.IsNotExist(err) {
			if !useJSON {
				fmt.Println("CAS is empty — nothing to collect")
			} else {
				enc := json.NewEncoder(os.Stdout)
				_ = enc.Encode(map[string]any{"freed_bytes": 0, "deleted": 0, "dry_run": *dryRunFlag})
			}
			return
		}
		die(useJSON, errors.CodeInternalError, "cas gc: read CAS: "+err.Error())
	}

	for _, prefix := range prefixes {
		if !prefix.IsDir() {
			continue
		}
		suffixDir := filepath.Join(sha256Dir, prefix.Name())
		entries, readErr := os.ReadDir(suffixDir)
		if readErr != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			hexFull := prefix.Name() + entry.Name()
			if _, ok := referenced[hexFull]; ok {
				continue // still referenced
			}
			info, statErr := entry.Info()
			if statErr != nil {
				continue
			}
			candidates = append(candidates, gcEntry{
				Digest: "sha256:" + hexFull,
				Size:   info.Size(),
			})
		}
	}

	var freedBytes int64
	if !*dryRunFlag && len(candidates) > 0 && !*yesFlag && !useJSON {
		var totalSize int64
		for _, c := range candidates {
			totalSize += c.Size
		}
		fmt.Printf("cas gc: %d unreferenced blob(s) totalling %d bytes will be permanently deleted.\n", len(candidates), totalSize)
		fmt.Print("Confirm deletion? [y/N] ")
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() || strings.ToLower(strings.TrimSpace(scanner.Text())) != "y" {
			fmt.Println("Aborted. Run with --yes to skip this prompt, or --dry-run to preview.")
			return
		}
	}
	for i := range candidates {
		blobPath := filepath.Join(sha256Dir, candidates[i].Digest[7:9], candidates[i].Digest[9:])
		if *dryRunFlag {
			candidates[i].Deleted = false
		} else {
			if removeErr := os.Remove(blobPath); removeErr != nil && !os.IsNotExist(removeErr) {
				candidates[i].Error = removeErr.Error()
			} else {
				candidates[i].Deleted = true
				freedBytes += candidates[i].Size
			}
		}
		if *dryRunFlag {
			freedBytes += candidates[i].Size
		}
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"dry_run":     *dryRunFlag,
			"freed_bytes": freedBytes,
			"deleted":     len(candidates),
			"blobs":       candidates,
		})
		return
	}

	if len(candidates) == 0 {
		fmt.Println("cas gc: no unreferenced blobs found")
		return
	}
	verb := "deleted"
	if *dryRunFlag {
		verb = "would delete"
	}
	for _, c := range candidates {
		if c.Error != "" {
			fmt.Printf("FAIL  %s — %s\n", c.Digest, c.Error)
		} else {
			fmt.Printf("%s  %s  (%d bytes)\n", verb, c.Digest, c.Size)
		}
	}
	fmt.Printf("\n%s %d blob(s), freed %d bytes\n", verb, len(candidates), freedBytes)
	if *dryRunFlag {
		fmt.Println("Run without --dry-run to actually delete")
	}
}
