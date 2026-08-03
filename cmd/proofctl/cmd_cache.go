package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
)

func cmdCache(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl cache <subcommand>\n  subcommands: audit")
	}

	switch args[0] {
	case "audit":
		cmdCacheAudit(useJSON)
	default:
		die(useJSON, errors.CodeInvalidInput, "unknown cache subcommand: "+args[0])
	}
}

func cmdCacheAudit(useJSON bool) {
	cwd, err := os.Getwd()
	if err != nil {
		die(useJSON, errors.CodeInternalError, err.Error())
	}
	root, err := config.Find(cwd)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	casRoot := filepath.Join(root, config.DirName, config.CASDir)
	store, err := cas.New(casRoot)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "cannot open CAS: "+err.Error())
	}
	_ = store

	type blobEntry struct {
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
	}

	var blobs []blobEntry
	sha256Dir := filepath.Join(casRoot, "sha256")
	prefixes, err := os.ReadDir(sha256Dir)
	if err != nil {
		if os.IsNotExist(err) {
			if useJSON {
				enc := json.NewEncoder(os.Stdout)
				_ = enc.Encode([]blobEntry{})
			} else {
				fmt.Println("CAS is empty.")
			}
			return
		}
		die(useJSON, errors.CodeInternalError, "cannot read CAS: "+err.Error())
	}

	for _, prefix := range prefixes {
		if !prefix.IsDir() {
			continue
		}
		suffixDir := filepath.Join(sha256Dir, prefix.Name())
		entries, err := os.ReadDir(suffixDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			digest := "sha256:" + prefix.Name() + entry.Name()
			blobs = append(blobs, blobEntry{Digest: digest, Size: info.Size()})
		}
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(blobs)
		return
	}

	if len(blobs) == 0 {
		fmt.Println("CAS is empty.")
		return
	}
	for _, b := range blobs {
		fmt.Printf("%s  %d bytes\n", b.Digest, b.Size)
	}
}
