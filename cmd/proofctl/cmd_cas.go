package main

import (
	"encoding/json"
	"flag"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/compile"
	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
)

func cmdCas(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl cas <import|list> ...")
	}
	switch args[0] {
	case "import":
		cmdCasImport(args[1:], useJSON)
	case "list":
		cmdCasList(args[1:], useJSON)
	default:
		die(useJSON, errors.CodeInvalidInput, "unknown cas subcommand "+args[0]+"; use import or list")
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
		updated := false
		if idx, ok := evidenceIdx[digest]; ok {
			if pg.Evidence[idx].Size != size {
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
