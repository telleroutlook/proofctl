package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	qmdpkg "github.com/telleroutlook/proofctl/adapters/qmd"
	"github.com/telleroutlook/proofctl/internal/compile"
	"github.com/telleroutlook/proofctl/internal/config"
	"github.com/telleroutlook/proofctl/internal/dag"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/kernel/contract"
	weilpkg "github.com/telleroutlook/proofctl/internal/weil"
)

// cmdCompile implements the compile subcommand.
//
// Usage:
//
//	proofctl compile [--adapter weil|json|qmd] [--fix-digests] <source-file>
func cmdCompile(args []string, useJSON bool) {
	fs := flag.NewFlagSet("compile", flag.ContinueOnError)
	adapterFlag := fs.String("adapter", "json", "adapter type: json, weil, qmd, or contract-dir")
	fixDigestsFlag := fs.Bool("fix-digests", false, "compute and fill in zero statement.digest fields before compiling")
	forceFlag := fs.Bool("force", false, "overwrite existing real attestations with shadow attestations (weil adapter only)")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "compile: "+err.Error())
	}
	if fs.NArg() == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl compile [--adapter weil|json|qmd|contract-dir] [--fix-digests] <source-file-or-dir>")
	}
	srcFile := fs.Arg(0)

	// contract-dir reads a directory; skip the file-read and fix-digests steps.
	if *adapterFlag == "contract-dir" {
		cwd, err := os.Getwd()
		if err != nil {
			die(useJSON, errors.CodeInternalError, "getcwd: "+err.Error())
		}
		root, err := config.Find(cwd)
		if err != nil {
			die(useJSON, errors.CodeInvalidInput, err.Error())
		}
		pg, err := compileContractDir(srcFile, useJSON)
		if err != nil {
			die(useJSON, errors.CodeInvalidInput, err.Error())
		}
		g := dag.New()
		for i := range pg.Claims {
			if addErr := g.AddClaim(&pg.Claims[i]); addErr != nil {
				die(useJSON, errors.CodeDuplicateID, addErr.Error())
			}
		}
		if valErr := g.Validate(); valErr != nil {
			die(useJSON, errors.CodeCycleDetected, valErr.Error())
		}
		outPath := filepath.Join(root, config.DirName, config.GraphFile)
		if writeErr := atomicWriteJSON(outPath, pg); writeErr != nil {
			die(useJSON, errors.CodeInternalError, "cannot write graph.json: "+writeErr.Error())
		}
		if useJSON {
			enc := json.NewEncoder(os.Stdout)
			_ = enc.Encode(map[string]any{"claims": len(pg.Claims), "adapter": "contract-dir", "graph": outPath})
		} else {
			fmt.Printf("Compiled %d claims from %s [adapter: contract-dir]\n", len(pg.Claims), srcFile)
		}
		return
	}

	src, err := os.ReadFile(srcFile)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("cannot read source file %s: %v", srcFile, err))
	}

	// --fix-digests: compute sha256(statement.text) for any all-zero digest, rewrite the source file.
	if *fixDigestsFlag {
		src, err = fixStatementDigests(src, srcFile, useJSON)
		if err != nil {
			die(useJSON, errors.CodeInvalidInput, "fix-digests: "+err.Error())
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		die(useJSON, errors.CodeInternalError, "getcwd: "+err.Error())
	}
	root, err := config.Find(cwd)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	var pg *ir.ProofGraph
	var shadowAttestations map[string]*ir.Attestation
	isShadow := false
	var qmdAdapter *qmdpkg.Adapter

	switch *adapterFlag {
	case "weil":
		isShadow = true
		pg, shadowAttestations, err = compileWeil(src)
		if err != nil {
			die(useJSON, errors.CodeInvalidInput, err.Error())
		}
	case "json":
		pg, err = compile.Compile(src, compile.FormatJSON)
		if err != nil {
			die(useJSON, errors.CodeInvalidInput, err.Error())
		}
	case "qmd":
		qmdAdapter = qmdpkg.DefaultAdapter()
		pg, err = qmdAdapter.Compile(src)
		if err != nil {
			die(useJSON, errors.CodeInvalidInput, err.Error())
		}
	default:
		die(useJSON, errors.CodeInvalidInput, "unknown adapter: "+*adapterFlag+"; use json, weil, qmd, or contract-dir")
	}

	g := dag.New()
	for i := range pg.Claims {
		if addErr := g.AddClaim(&pg.Claims[i]); addErr != nil {
			die(useJSON, errors.CodeDuplicateID, addErr.Error())
		}
	}
	if valErr := g.Validate(); valErr != nil {
		die(useJSON, errors.CodeCycleDetected, valErr.Error())
	}

	outPath := filepath.Join(root, config.DirName, config.GraphFile)
	if writeErr := atomicWriteJSON(outPath, pg); writeErr != nil {
		die(useJSON, errors.CodeInternalError, "cannot write graph.json: "+writeErr.Error())
	}

	if isShadow && len(shadowAttestations) > 0 {
		attestDir := filepath.Join(root, config.DirName, config.AttestDir)
		if mkErr := os.MkdirAll(attestDir, 0o755); mkErr != nil {
			die(useJSON, errors.CodeInternalError, "cannot create attestations dir: "+mkErr.Error())
		}
		var skipped []string
		for claimID, att := range shadowAttestations {
			attPath := filepath.Join(attestDir, claimID+".json")
			if existing, readErr := os.ReadFile(attPath); readErr == nil {
				var existingAtt ir.Attestation
				if jsonErr := json.Unmarshal(existing, &existingAtt); jsonErr == nil {
					if isHigherAssurance(existingAtt.Assurance) && !*forceFlag {
						skipped = append(skipped, claimID)
						if !useJSON {
							fmt.Fprintf(os.Stderr, "warn: skipping shadow overwrite for %s (existing assurance: %s) — use --force to overwrite\n",
								claimID, existingAtt.Assurance)
						}
						continue
					}
				}
			}
			if writeErr := atomicWriteJSON(attPath, att); writeErr != nil {
				die(useJSON, errors.CodeInternalError, "cannot write attestation "+claimID+": "+writeErr.Error())
			}
		}
		if useJSON && len(skipped) > 0 {
			// Include skipped list in JSON output below.
			_ = skipped
		}
	}

	if useJSON {
		out := map[string]any{
			"claims":  len(pg.Claims),
			"adapter": *adapterFlag,
			"graph":   outPath,
		}
		if isShadow {
			out["shadow"] = true
		}
		if qmdAdapter != nil && len(qmdAdapter.Identity.PandocAPIVersion) > 0 {
			out["pandoc_api_version"] = joinInts(qmdAdapter.Identity.PandocAPIVersion)
		}
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(out)
	} else {
		switch *adapterFlag {
		case "weil":
			fmt.Printf("Compiled %d claims from %s [adapter: weil, shadow mode]\n", len(pg.Claims), srcFile)
		case "qmd":
			pandocVer := ""
			if qmdAdapter != nil && len(qmdAdapter.Identity.PandocAPIVersion) > 0 {
				pandocVer = joinInts(qmdAdapter.Identity.PandocAPIVersion)
			}
			fmt.Printf("Compiled %d claims from %s [adapter: qmd, pandoc-api: %s]\n", len(pg.Claims), srcFile, pandocVer)
		case "contract-dir":
			fmt.Printf("Compiled %d claims from %s [adapter: contract-dir]\n", len(pg.Claims), srcFile)
		default:
			fmt.Printf("Compiled %d claims from %s\n", len(pg.Claims), srcFile)
		}
	}
}

// compileWeil compiles src using the Weil adapter in shadow mode.
func compileWeil(src []byte) (*ir.ProofGraph, map[string]*ir.Attestation, error) {
	pg, err := compile.Compile(src, compile.FormatJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("weil adapter: %w", err)
	}

	defects := weilpkg.DefectsByClaimID()
	atts := make(map[string]*ir.Attestation, len(pg.Claims))
	for i := range pg.Claims {
		c := &pg.Claims[i]
		if defect, ok := defects[c.ID]; ok {
			atts[c.ID] = weilpkg.BuildShadowAttestation(c, defect)
		} else {
			atts[c.ID] = weilpkg.BuildOpenAttestation(c)
		}
	}
	return pg, atts, nil
}

// isHigherAssurance reports whether assurance represents a real (non-shadow) verification
// that should not be silently overwritten by a shadow attestation.
func isHigherAssurance(a ir.Assurance) bool {
	return ir.AssuranceLevel(a) > 0
}

// joinInts converts a slice of ints to a dot-separated version string.
func joinInts(nums []int) string {
	parts := make([]string, len(nums))
	for i, v := range nums {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ".")
}

// zeroDigest is the placeholder used in graph templates.
const zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// compileContractDir reads all ContractV2 JSON files from dir and converts
// them into a ProofGraph. Each contract becomes one Claim; dependency edges
// are derived from contract.Dependencies[].claim_id.
func compileContractDir(dir string, useJSON bool) (*ir.ProofGraph, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("contract-dir: cannot read directory %q: %w", dir, err)
	}

	var pg ir.ProofGraph
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("contract-dir: read %s: %w", entry.Name(), err)
		}

		var c contract.ContractV2
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("contract-dir: parse %s: %w", entry.Name(), err)
		}

		if lintErrs := contract.LintContract(c); len(lintErrs) > 0 && !useJSON {
			fmt.Fprintf(os.Stderr, "warn: contract %s has %d lint error(s) — included anyway:\n", entry.Name(), len(lintErrs))
			for _, e := range lintErrs {
				fmt.Fprintf(os.Stderr, "  [%s] %s: %s\n", e.Code, e.Field, e.Message)
			}
		}

		deps := make([]string, 0, len(c.Dependencies))
		for _, d := range c.Dependencies {
			deps = append(deps, d.ClaimID)
		}

		pg.Claims = append(pg.Claims, ir.Claim{
			ID:   c.ClaimID,
			Kind: "theorem",
			Statement: ir.Statement{
				Digest: c.StatementDigest,
			},
			DependsOn:         deps,
			RequiredAssurance: c.Assurance.Required,
		})
	}

	if len(pg.Claims) == 0 {
		return nil, fmt.Errorf("contract-dir: no ContractV2 JSON files found in %q", dir)
	}
	return &pg, nil
}

// fixStatementDigests parses src as ProofGraph JSON, computes sha256(statement.text)
// for every claim whose statement.digest is zero, rewrites srcFile, and returns the
// updated JSON bytes.
func fixStatementDigests(src []byte, srcFile string, useJSON bool) ([]byte, error) {
	pg, err := compile.Compile(src, compile.FormatJSON)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	fixed := 0
	for i := range pg.Claims {
		c := &pg.Claims[i]
		if c.Statement.Digest == "" || c.Statement.Digest == zeroDigest {
			c.Statement.Digest = ir.StatementDigest(c.Statement.Text)
			fixed++
		}
	}

	if fixed == 0 {
		return src, nil
	}

	data, _ := json.MarshalIndent(pg, "", "  ")
	data = append(data, '\n')
	if err := os.WriteFile(srcFile, data, 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", srcFile, err)
	}
	if !useJSON {
		fmt.Printf("fix-digests: computed %d statement digest(s) in %s\n", fixed, srcFile)
	}
	return data, nil
}
