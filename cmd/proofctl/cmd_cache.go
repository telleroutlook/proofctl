package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
)

func cmdCache(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput,
			"usage: proofctl cache <subcommand>\n  subcommands: audit, invalidate, show-key")
	}

	switch args[0] {
	case "audit":
		cmdCacheAudit(useJSON)
	case "invalidate":
		cmdCacheInvalidate(args[1:], useJSON)
	case "show-key":
		cmdCacheShowKey(args[1:], useJSON)
	default:
		die(useJSON, errors.CodeInvalidInput, "unknown cache subcommand: "+args[0]+
			"; use audit, invalidate, or show-key")
	}
}

// cmdCacheInvalidate removes the attestation file(s) for the given claim IDs,
// forcing a full re-run on the next proofctl check invocation.
func cmdCacheInvalidate(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl cache invalidate <claim-id> [claim-id ...]")
	}

	cwd, err := os.Getwd()
	if err != nil {
		die(useJSON, errors.CodeInternalError, err.Error())
	}
	root, err := config.Find(cwd)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	attestDir := filepath.Join(root, config.DirName, config.AttestDir)

	type result struct {
		ClaimID string `json:"claim_id"`
		Done    bool   `json:"done"`
		Note    string `json:"note,omitempty"`
	}
	var results []result

	for _, claimID := range args {
		attPath := filepath.Join(attestDir, claimID+".json")
		if err := os.Remove(attPath); err != nil {
			if os.IsNotExist(err) {
				results = append(results, result{ClaimID: claimID, Done: true, Note: "no cached attestation"})
			} else {
				results = append(results, result{ClaimID: claimID, Done: false, Note: err.Error()})
			}
		} else {
			results = append(results, result{ClaimID: claimID, Done: true})
		}
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}
	for _, r := range results {
		if !r.Done {
			fmt.Fprintf(os.Stderr, "FAIL  %s — %s\n", r.ClaimID, r.Note)
		} else if r.Note != "" {
			fmt.Printf("OK    %s (%s)\n", r.ClaimID, r.Note)
		} else {
			fmt.Printf("OK    %s — attestation removed; next check will re-run\n", r.ClaimID)
		}
	}
}

// cmdCacheShowKey prints the cache key stored in the current attestation for a
// claim, along with an explanation of what inputs compose it.
func cmdCacheShowKey(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl cache show-key <claim-id>")
	}
	claimID := strings.TrimPrefix(args[0], "@")

	cwd, err := os.Getwd()
	if err != nil {
		die(useJSON, errors.CodeInternalError, err.Error())
	}
	root, err := config.Find(cwd)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	attPath := filepath.Join(root, config.DirName, config.AttestDir, claimID+".json")
	f, err := os.Open(attPath)
	if err != nil {
		if os.IsNotExist(err) {
			die(useJSON, errors.CodeInvalidInput,
				fmt.Sprintf("cache show-key: no attestation for %q — run 'proofctl check' first", claimID))
		}
		die(useJSON, errors.CodeInternalError, "cache show-key: "+err.Error())
	}
	att, decErr := ir.DecodeAttestation(f)
	_ = f.Close()
	if decErr != nil {
		die(useJSON, errors.CodeInvalidInput, "cache show-key: decode attestation: "+decErr.Error())
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"claim_id":       att.ClaimID,
			"cache_key":      att.CacheKey,
			"assurance":      string(att.Assurance),
			"checker_id":     att.Checker.ID,
			"checker_digest": att.Checker.CheckerDigest,
			"evidence_count": len(att.Evidence),
		})
		return
	}

	if att.CacheKey == "" {
		fmt.Printf("claim:   %s\ncache_key: (none — attestation was written manually)\n", claimID)
		return
	}
	fmt.Printf("claim:           %s\n", claimID)
	fmt.Printf("cache_key:       %s\n", att.CacheKey)
	fmt.Printf("checker:         %s  digest=%s\n", att.Checker.ID, att.Checker.CheckerDigest)
	fmt.Printf("evidence count:  %d\n", len(att.Evidence))
	fmt.Printf("assurance:       %s\n", att.Assurance)
	fmt.Println()
	fmt.Println("The cache key covers: claim statement digest, dependency statement digests,")
	fmt.Println("evidence digests, checker digest, checker schema digest, policy digest,")
	fmt.Println("and (if reported by checker) the toolchain map.")
	fmt.Println()
	fmt.Println("To force re-verification: proofctl cache invalidate " + claimID)
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
