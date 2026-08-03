// Package main implements the proofctl CLI.
//
// Subcommands:
//
//	init      Initialize a new proof graph project
//	compile   Compile a proof source file to ProofGraph IR
//	check     Run checkers for one or more claims
//	verify    Verify attestation integrity
//	explain   Explain the status of a claim
//	graph     Print the claim dependency graph
//	frontier  List the unresolved direct dependencies of a claim
//	impact    List claims that depend on a given claim
//	cache     Manage the checker result cache
//	release   Run the release gate
//	status    Print the current proof graph status
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"context"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/compile"
	"github.com/telleroutlook/proofctl/internal/config"
	"github.com/telleroutlook/proofctl/internal/dag"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
	"github.com/telleroutlook/proofctl/internal/release"
	"github.com/telleroutlook/proofctl/internal/runner"
	"github.com/telleroutlook/proofctl/internal/status"
	"github.com/telleroutlook/proofctl/internal/verify"
	weilpkg "github.com/telleroutlook/proofctl/internal/weil"
)

func main() {
	jsonFlag := flag.Bool("json", false, "output in JSON format")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "init":
		cmdInit(subargs, *jsonFlag)
	case "compile":
		cmdCompile(subargs, *jsonFlag)
	case "check":
		cmdCheck(subargs, *jsonFlag)
	case "verify":
		cmdVerify(subargs, *jsonFlag)
	case "explain":
		cmdExplain(subargs, *jsonFlag)
	case "graph":
		cmdGraph(subargs, *jsonFlag)
	case "frontier":
		cmdFrontier(subargs, *jsonFlag)
	case "impact":
		cmdImpact(subargs, *jsonFlag)
	case "cache":
		cmdCache(subargs, *jsonFlag)
	case "release":
		cmdRelease(subargs, *jsonFlag)
	case "status":
		cmdStatus(subargs, *jsonFlag)
	default:
		fmt.Fprintf(os.Stderr, "proofctl: unknown subcommand %q\n", subcmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `proofctl — Proof Graph Engine

Usage:
  proofctl [--json] <subcommand> [args...]

Subcommands:
  init      Initialize a new proof graph project
  compile   Compile a proof source file to ProofGraph IR
  check     Run checkers for one or more claims
  verify    Verify attestation integrity
  explain   Explain the status of a claim
  graph     Print the claim dependency graph
  frontier  List unresolved direct dependencies of a claim
  impact    List claims that depend on a given claim
  cache     Manage the checker result cache
  release   Run the release gate
  status    Print the current proof graph status

Flags:
  --json    Output in JSON format`)
}

// die prints an error and exits with code 1.
func die(useJSON bool, code, msg string) {
	if useJSON {
		enc := json.NewEncoder(os.Stderr)
		_ = enc.Encode(errors.New(code, msg))
	} else {
		fmt.Fprintln(os.Stderr, "error:", msg)
	}
	os.Exit(1)
}

// loadProjectGraph finds the project root, loads config, graph and attestations.
// Returns the root, config, DAG, and attestation map.
func loadProjectGraph(useJSON bool) (string, *config.ProjectConfig, *dag.DAG, map[string]*ir.Attestation) {
	cwd, err := os.Getwd()
	if err != nil {
		die(useJSON, errors.CodeInternalError, "cannot determine working directory: "+err.Error())
	}

	root, err := config.Find(cwd)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	cfg, err := config.Load(root)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	graphPath := filepath.Join(root, config.DirName, config.GraphFile)
	graphData, err := os.ReadFile(graphPath)
	if err != nil {
		if os.IsNotExist(err) {
			if useJSON {
				enc := json.NewEncoder(os.Stdout)
				_ = enc.Encode(map[string]any{"error": "No proof graph found. Run 'proofctl compile' first."})
			} else {
				fmt.Println("No proof graph found. Run 'proofctl compile' first.")
			}
			os.Exit(0)
		}
		die(useJSON, errors.CodeInternalError, "cannot read graph.json: "+err.Error())
	}

	pg, err := compile.Compile(graphData, compile.FormatJSON)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, "graph.json invalid: "+err.Error())
	}

	g := dag.New()
	for i := range pg.Claims {
		if err := g.AddClaim(&pg.Claims[i]); err != nil {
			die(useJSON, errors.CodeDuplicateID, err.Error())
		}
	}
	if err := g.Validate(); err != nil {
		die(useJSON, errors.CodeCycleDetected, err.Error())
	}

	attestations := loadAttestations(root, useJSON)
	return root, cfg, g, attestations
}

// loadAttestations reads all JSON files in the attestations directory.
func loadAttestations(root string, useJSON bool) map[string]*ir.Attestation {
	attestDir := filepath.Join(root, config.DirName, config.AttestDir)
	entries, err := os.ReadDir(attestDir)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]*ir.Attestation)
		}
		die(useJSON, errors.CodeInternalError, "cannot read attestations directory: "+err.Error())
	}

	attestations := make(map[string]*ir.Attestation)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(attestDir, entry.Name())
		f, err := os.Open(path)
		if err != nil {
			die(useJSON, errors.CodeInternalError, "cannot open attestation "+entry.Name()+": "+err.Error())
		}
		att, err := ir.DecodeAttestation(f)
		_ = f.Close()
		if err != nil {
			die(useJSON, errors.CodeInvalidInput, "invalid attestation "+entry.Name()+": "+err.Error())
		}
		attestations[att.ClaimID] = att
	}
	return attestations
}

// loadPolicy reads and parses the policy file at path.
func loadPolicy(path string, useJSON bool) policy.ReleasePolicy {
	data, err := os.ReadFile(path)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, "cannot read policy file: "+err.Error())
	}
	var pol policy.ReleasePolicy
	if err := json.Unmarshal(data, &pol); err != nil {
		die(useJSON, errors.CodeInvalidInput, "cannot parse policy file: "+err.Error())
	}
	return pol
}

// cmdInit implements the init subcommand.
func cmdInit(args []string, useJSON bool) {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "cannot resolve path: "+err.Error())
	}
	if err := config.Init(abs); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}
	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(map[string]string{"initialized": abs})
	} else {
		fmt.Printf("Initialized .proofctl in %s\n", abs)
	}
}

// cmdCompile implements the compile subcommand.
//
// Usage:
//
//	proofctl compile [--adapter weil|json] <source-file>
func cmdCompile(args []string, useJSON bool) {
	fs := flag.NewFlagSet("compile", flag.ContinueOnError)
	adapterFlag := fs.String("adapter", "json", "adapter type: json or weil")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "compile: "+err.Error())
	}
	if fs.NArg() == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl compile [--adapter weil|json] <source-file>")
	}
	srcFile := fs.Arg(0)
	src, err := os.ReadFile(srcFile)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, "cannot read source file: "+err.Error())
	}

	// Find project root.
	cwd, err := os.Getwd()
	if err != nil {
		die(useJSON, errors.CodeInternalError, err.Error())
	}
	root, err := config.Find(cwd)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	var pg *ir.ProofGraph
	var shadowAttestations map[string]*ir.Attestation
	isShadow := false

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
	default:
		die(useJSON, errors.CodeInvalidInput, "unknown adapter: "+*adapterFlag+"; use json or weil")
	}

	// Build and validate DAG.
	g := dag.New()
	for i := range pg.Claims {
		if addErr := g.AddClaim(&pg.Claims[i]); addErr != nil {
			die(useJSON, errors.CodeDuplicateID, addErr.Error())
		}
	}
	if valErr := g.Validate(); valErr != nil {
		die(useJSON, errors.CodeCycleDetected, valErr.Error())
	}

	// Write graph.json atomically.
	outPath := filepath.Join(root, config.DirName, config.GraphFile)
	if writeErr := atomicWriteJSON(outPath, pg); writeErr != nil {
		die(useJSON, errors.CodeInternalError, "cannot write graph.json: "+writeErr.Error())
	}

	// Write shadow attestations if using weil adapter.
	if isShadow && len(shadowAttestations) > 0 {
		attestDir := filepath.Join(root, config.DirName, config.AttestDir)
		if mkErr := os.MkdirAll(attestDir, 0o755); mkErr != nil {
			die(useJSON, errors.CodeInternalError, "cannot create attestations dir: "+mkErr.Error())
		}
		for claimID, att := range shadowAttestations {
			attPath := filepath.Join(attestDir, claimID+".json")
			if writeErr := atomicWriteJSON(attPath, att); writeErr != nil {
				die(useJSON, errors.CodeInternalError, "cannot write attestation "+claimID+": "+writeErr.Error())
			}
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
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(out)
	} else {
		suffix := ""
		if isShadow {
			suffix = " [adapter: weil, shadow mode]"
		}
		fmt.Printf("Compiled %d claims from %s%s\n", len(pg.Claims), srcFile, suffix)
	}
}

// compileWeil compiles a source file using the Weil adapter in shadow mode.
// It returns the ProofGraph and a map of shadow attestations keyed by claim ID.
// The source file is expected to be a JSON ProofGraph; the weil adapter
// annotates each claim with shadow attestations from the known-defect table.
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

// atomicWriteJSON marshals v as indented JSON and writes it atomically to path
// using a temp file + rename pattern.
func atomicWriteJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()

	if _, writeErr := tmp.Write(data); writeErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp: %w", writeErr)
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("sync: %w", syncErr)
	}
	if closeErr := tmp.Close(); closeErr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close: %w", closeErr)
	}
	if renameErr := os.Rename(tmpName, path); renameErr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename: %w", renameErr)
	}
	return nil
}

// cmdStatus implements the status subcommand.
func cmdStatus(_ []string, useJSON bool) {
	_, _, g, attestations := loadProjectGraph(useJSON)

	statuses := status.Compute(g, attestations)

	// Build topological order (leaf claims first, main theorem last).
	topoOrder, topoErr := topoSort(g)
	if topoErr != nil {
		// Fall back to sorted IDs if topo sort fails (should not happen after Validate).
		topoOrder = make([]string, 0, len(statuses))
		for id := range statuses {
			topoOrder = append(topoOrder, id)
		}
		sort.Strings(topoOrder)
	}

	if useJSON {
		type claimStatusEntry struct {
			Status      string `json:"status"`
			BlockReason string `json:"block_reason,omitempty"`
		}
		claimsMap := make(map[string]claimStatusEntry, len(statuses))
		for id, s := range statuses {
			entry := claimStatusEntry{Status: string(s)}
			if att, ok := attestations[id]; ok && att.BlockReason != "" {
				entry.BlockReason = att.BlockReason
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
			Claims          map[string]claimStatusEntry `json:"claims"`
			Summary         summaryEntry                `json:"summary"`
			CertifiedRadius interface{}                 `json:"certified_radius"`
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(statusOutput{Claims: claimsMap, Summary: summ, CertifiedRadius: nil})
		return
	}

	// Human output: topological order table with block reasons.
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
		reason := ""
		if att, ok := attestations[id]; ok && att.BlockReason != "" {
			reason = "  " + att.BlockReason
		} else if s == ir.StatusOpen {
			reason = "  (no attestation)"
		}
		fmt.Printf("%-40s %-10s%s\n", id, strings.ToUpper(string(s)), reason)
	}
	fmt.Printf("\nSummary: %d accepted, %d blocked, %d open, %d rejected\n",
		accepted, blocked, open, rejected)
	fmt.Println("certified_radius: null")
}

// cmdGraph implements the graph subcommand.
func cmdGraph(args []string, useJSON bool) {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	targetFlag := fs.String("target", "", "show closure for @claim-id")
	showStatusFlag := fs.Bool("show-status", false, "show claim status inline")
	_ = fs.Parse(args)

	_, _, g, attestations := loadProjectGraph(useJSON)

	target := strings.TrimPrefix(*targetFlag, "@")

	// Compute statuses if requested.
	var statuses map[string]ir.Status
	if *showStatusFlag {
		statuses = status.Compute(g, attestations)
	}

	type claimNode struct {
		ID        string   `json:"id"`
		Kind      string   `json:"kind"`
		Status    string   `json:"status,omitempty"`
		DependsOn []string `json:"depends_on"`
	}

	if useJSON {
		var nodes []claimNode
		claims := g.Claims()
		if target != "" {
			if g.Claim(target) == nil {
				die(useJSON, errors.CodeMissingDependency, "unknown claim: "+target)
			}
			closure, err := g.Closure(target)
			if err != nil {
				die(useJSON, errors.CodeInternalError, err.Error())
			}
			claimSet := make(map[string]bool)
			claimSet[target] = true
			for _, id := range closure {
				claimSet[id] = true
			}
			for _, c := range claims {
				if claimSet[c.ID] {
					node := claimNode{ID: c.ID, Kind: c.Kind, DependsOn: c.DependsOn}
					if statuses != nil {
						node.Status = string(statuses[c.ID])
					}
					nodes = append(nodes, node)
				}
			}
		} else {
			for _, c := range claims {
				node := claimNode{ID: c.ID, Kind: c.Kind, DependsOn: c.DependsOn}
				if statuses != nil {
					node.Status = string(statuses[c.ID])
				}
				nodes = append(nodes, node)
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(nodes)
		return
	}

	claims := g.Claims()
	for _, c := range claims {
		if target != "" {
			closure, err := g.Closure(target)
			if err != nil {
				die(useJSON, errors.CodeInternalError, err.Error())
			}
			claimSet := make(map[string]bool)
			claimSet[target] = true
			for _, id := range closure {
				claimSet[id] = true
			}
			if !claimSet[c.ID] {
				continue
			}
		}
		deps := strings.Join(c.DependsOn, ", ")
		if deps == "" {
			deps = "(no deps)"
		}
		if statuses != nil {
			fmt.Printf("%s [%s] %s -> %s\n", c.ID, c.Kind, strings.ToUpper(string(statuses[c.ID])), deps)
		} else {
			fmt.Printf("%s [%s] -> %s\n", c.ID, c.Kind, deps)
		}
	}
}

// cmdFrontier implements the frontier subcommand.
func cmdFrontier(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl frontier @<claim-id>")
	}
	claimID := strings.TrimPrefix(args[0], "@")

	_, _, g, attestations := loadProjectGraph(useJSON)

	if g.Claim(claimID) == nil {
		die(useJSON, errors.CodeMissingDependency, "unknown claim: "+claimID)
	}

	directDeps, err := g.Frontier(claimID)
	if err != nil {
		die(useJSON, errors.CodeInternalError, err.Error())
	}

	// Filter to only deps that are not yet accepted.
	var frontier []string
	for _, depID := range directDeps {
		att, ok := attestations[depID]
		if !ok || att.Outcome != string(ir.StatusAccepted) {
			frontier = append(frontier, depID)
		}
	}
	sort.Strings(frontier)

	if useJSON {
		type frontierOutput struct {
			Claim    string   `json:"claim"`
			Frontier []string `json:"frontier"`
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(frontierOutput{Claim: claimID, Frontier: frontier})
		return
	}

	if len(frontier) == 0 {
		fmt.Printf("No unresolved direct dependencies for %s\n", claimID)
		return
	}
	fmt.Printf("Unresolved direct dependencies of %s:\n", claimID)
	for _, dep := range frontier {
		fmt.Printf("  %s\n", dep)
	}
}

// cmdImpact implements the impact subcommand.
func cmdImpact(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl impact @<claim-id>")
	}
	claimID := strings.TrimPrefix(args[0], "@")

	_, _, g, _ := loadProjectGraph(useJSON)

	if g.Claim(claimID) == nil {
		die(useJSON, errors.CodeMissingDependency, "unknown claim: "+claimID)
	}

	impact, err := g.Impact(claimID)
	if err != nil {
		die(useJSON, errors.CodeInternalError, err.Error())
	}
	sort.Strings(impact)

	if useJSON {
		type impactOutput struct {
			Claim  string   `json:"claim"`
			Impact []string `json:"impact"`
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(impactOutput{Claim: claimID, Impact: impact})
		return
	}

	if len(impact) == 0 {
		fmt.Printf("No claims depend on %s\n", claimID)
		return
	}
	fmt.Printf("Claims that depend on %s:\n", claimID)
	for _, id := range impact {
		fmt.Printf("  %s\n", id)
	}
}

// cmdExplain implements the explain subcommand.
func cmdExplain(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl explain @<claim-id>")
	}
	claimID := strings.TrimPrefix(args[0], "@")

	_, _, g, attestations := loadProjectGraph(useJSON)

	c := g.Claim(claimID)
	if c == nil {
		die(useJSON, errors.CodeMissingDependency, "unknown claim: "+claimID)
	}

	statuses := status.Compute(g, attestations)
	claimStatus := statuses[claimID]
	att := attestations[claimID]

	if useJSON {
		type explainOutput struct {
			ID          string          `json:"id"`
			Kind        string          `json:"kind"`
			Status      string          `json:"status"`
			Assurance   string          `json:"assurance,omitempty"`
			BlockReason string          `json:"block_reason,omitempty"`
			Statement   ir.Statement    `json:"statement"`
			DependsOn   []string        `json:"depends_on"`
			Attestation *ir.Attestation `json:"attestation,omitempty"`
		}
		out := explainOutput{
			ID:        c.ID,
			Kind:      c.Kind,
			Status:    string(claimStatus),
			Statement: c.Statement,
			DependsOn: c.DependsOn,
		}
		if att != nil {
			out.Assurance = string(att.Assurance)
			out.BlockReason = att.BlockReason
			out.Attestation = att
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	fmt.Printf("Claim:  %s\n", c.ID)
	fmt.Printf("Kind:   %s\n", c.Kind)
	fmt.Printf("Status: %s\n", strings.ToUpper(string(claimStatus)))
	if att != nil {
		assuranceNote := ""
		if att.Assurance == weilpkg.ShadowAssurance {
			assuranceNote = " (shadow mode — not eligible for release)"
		}
		fmt.Printf("Assurance: %s%s\n", att.Assurance, assuranceNote)
		if att.BlockReason != "" {
			fmt.Printf("Block reason: %s\n", att.BlockReason)
		}
	}
	if len(c.DependsOn) > 0 {
		fmt.Printf("Depends on: %s\n", strings.Join(c.DependsOn, ", "))
	}
	if claimStatus == ir.StatusBlocked && att == nil {
		// No direct attestation: show blocking deps.
		closure, _ := g.Closure(claimID)
		for _, depID := range closure {
			depAtt, ok := attestations[depID]
			if !ok {
				continue
			}
			if ir.Status(depAtt.Outcome) == ir.StatusDisproved ||
				ir.Status(depAtt.Outcome) == ir.StatusRejected ||
				ir.Status(depAtt.Outcome) == ir.StatusError {
				fmt.Printf("Blocker: %s (status: %s)\n", depID, depAtt.Outcome)
			}
		}
	}
}

// cmdCache implements the cache subcommand.
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

// cmdCacheAudit lists all blobs in the CAS with their digests and sizes.
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
	_ = store // store opened to ensure directory exists

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

// cmdRelease implements the release subcommand.
func cmdRelease(args []string, useJSON bool) {
	fs := flag.NewFlagSet("release", flag.ContinueOnError)
	targetFlag := fs.String("target", "", "target claim ID (@claim-id)")
	dryRunFlag := fs.Bool("dry-run", false, "dry run (do not write STATUS.json)")
	_ = fs.Parse(args)

	root, cfg, g, attestations := loadProjectGraph(useJSON)

	_ = strings.TrimPrefix(*targetFlag, "@")

	polPath := filepath.Join(root, cfg.PolicyFile)
	pol := loadPolicy(polPath, useJSON)

	gate := &release.Gate{OutputDir: filepath.Join(root, config.DirName)}

	type releaseOutput struct {
		Pass     bool     `json:"pass"`
		Blockers []string `json:"blockers"`
		Released bool     `json:"released"`
		Defects  map[string]string `json:"defects,omitempty"`
		CertifiedRadius interface{} `json:"certified_radius"`
	}

	// Collect D-defect reasons for human output.
	defects := collectDefects(attestations)

	if *dryRunFlag {
		pass, blockers := gate.DryRun(g, attestations, pol)
		if useJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			out := releaseOutput{Pass: pass, Blockers: blockers, Released: false, CertifiedRadius: nil}
			if len(defects) > 0 {
				out.Defects = defects
			}
			_ = enc.Encode(out)
			return
		}
		if pass {
			fmt.Println("RELEASE DRY-RUN: PASS")
		} else {
			fmt.Printf("RELEASE DRY-RUN: BLOCKED\nBlockers (%d):\n", len(blockers)+len(defects))
			for _, b := range blockers {
				fmt.Printf("  [POLICY] %s\n", b)
			}
			for claimID, reason := range defects {
				fmt.Printf("  [DEFECT] %s: %s\n", claimID, reason)
			}
			fmt.Println("\ncertified_radius: null")
		}
		return
	}

	pass, blockers, err := gate.Release(g, attestations, pol)
	if err != nil {
		die(useJSON, errors.CodeInternalError, err.Error())
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		out := releaseOutput{Pass: pass, Blockers: blockers, Released: pass, CertifiedRadius: nil}
		if pass {
			out.CertifiedRadius = pol.Target
		}
		if len(defects) > 0 {
			out.Defects = defects
		}
		_ = enc.Encode(out)
		return
	}

	if pass {
		fmt.Println("PASS: release gate passed")
		fmt.Printf("certified_radius: %s\n", pol.Target)
	} else {
		fmt.Printf("RELEASE BLOCKED\nBlockers (%d):\n", len(blockers)+len(defects))
		for _, b := range blockers {
			fmt.Printf("  [POLICY] %s\n", b)
		}
		for claimID, reason := range defects {
			fmt.Printf("  [DEFECT] %s: %s\n", claimID, reason)
		}
		fmt.Println("\ncertified_radius: null")
	}
}

// collectDefects returns a map of claim ID → block_reason for all blocked attestations.
func collectDefects(attestations map[string]*ir.Attestation) map[string]string {
	defects := make(map[string]string)
	for id, att := range attestations {
		if att.BlockReason != "" {
			defects[id] = att.BlockReason
		}
	}
	return defects
}

// cmdCheck implements the check subcommand (not yet implemented).
func cmdCheck(_ []string, useJSON bool) {
	if useJSON {
		enc := json.NewEncoder(os.Stderr)
		_ = enc.Encode(errors.New(errors.CodeNotImplemented, "check subcommand is not yet implemented"))
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "error: check subcommand is not yet implemented")
	os.Exit(1)
}

// cmdVerify implements the verify subcommand.
// Usage:
//
//	proofctl verify @<claim-id>
//	proofctl verify --project
func cmdVerify(args []string, useJSON bool) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	projectFlag := fs.Bool("project", false, "verify all open claims in dependency order")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "verify: "+err.Error())
	}

	root, _, g, _ := loadProjectGraph(useJSON)

	casRoot := filepath.Join(root, config.DirName, config.CASDir)
	store, err := cas.New(casRoot)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "cannot open CAS: "+err.Error())
	}

	attestDir := filepath.Join(root, config.DirName, config.AttestDir)

	nr := &runner.NativeRunner{}
	pipeline := &verify.Pipeline{
		DAG:       g,
		CAS:       store,
		AttestDir: attestDir,
		Runner:    nr,
	}

	// Determine which claims to verify.
	var targets []string
	if *projectFlag {
		// Topological order — all open claims.
		order, err := topoSort(g)
		if err != nil {
			die(useJSON, errors.CodeCycleDetected, err.Error())
		}
		// Reload attestations to skip already-accepted ones.
		attestations := loadAttestations(root, useJSON)
		for _, id := range order {
			att, ok := attestations[id]
			if ok && att.Outcome == string(ir.StatusAccepted) {
				continue
			}
			targets = append(targets, id)
		}
	} else {
		if len(fs.Args()) == 0 {
			die(useJSON, errors.CodeInvalidInput, "usage: proofctl verify @<claim-id> or --project")
		}
		targets = []string{strings.TrimPrefix(fs.Args()[0], "@")}
	}

	type verifyResult struct {
		ClaimID  string `json:"claim_id"`
		Outcome  string `json:"outcome"`
		Assurance string `json:"assurance"`
		CacheHit bool   `json:"cache_hit"`
		Error    string `json:"error,omitempty"`
	}

	var results []verifyResult
	exitCode := 0

	for _, claimID := range targets {
		claim := g.Claim(claimID)
		if claim == nil {
			if useJSON {
				results = append(results, verifyResult{ClaimID: claimID, Outcome: "error", Error: "unknown claim"})
			} else {
				fmt.Printf("ERROR %s: unknown claim\n", claimID)
			}
			exitCode = 1
			continue
		}

		// Find a matching checker from graph's Checkers list by checker_policy on the claim.
		pg := loadRawGraph(root, useJSON)
		checkerID, found := findChecker(pg, claim.CheckerPolicy)
		if !found {
			if useJSON {
				results = append(results, verifyResult{ClaimID: claimID, Outcome: "error", Error: "no checker for policy " + claim.CheckerPolicy})
			} else {
				fmt.Printf("ERROR %s: no checker for policy %q\n", claimID, claim.CheckerPolicy)
			}
			exitCode = 1
			continue
		}

		// Find matching evidence descriptors by digest refs on the claim.
		evidence := findEvidence(pg, claim.Evidence)

		res, runErr := pipeline.Run(context.Background(), claimID, checkerID, evidence, "")
		if runErr != nil {
			if useJSON {
				results = append(results, verifyResult{ClaimID: claimID, Outcome: "error", Error: runErr.Error()})
			} else {
				fmt.Printf("FAIL %s: %v\n", claimID, runErr)
			}
			exitCode = 1
			continue
		}

		cacheNote := ""
		if res.CacheHit {
			cacheNote = " [cache-hit]"
		}
		if useJSON {
			results = append(results, verifyResult{
				ClaimID:  claimID,
				Outcome:  res.Attestation.Outcome,
				Assurance: string(res.Attestation.Assurance),
				CacheHit: res.CacheHit,
			})
		} else {
			if res.Attestation.Outcome == "accepted" {
				fmt.Printf("PASS %s%s\n", claimID, cacheNote)
			} else {
				fmt.Printf("FAIL %s: outcome=%s%s\n", claimID, res.Attestation.Outcome, cacheNote)
				exitCode = 1
			}
		}
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	}

	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

// topoSort returns all claim IDs in topological order (dependencies before dependents).
func topoSort(g *dag.DAG) ([]string, error) {
	claims := g.Claims()
	inDegree := make(map[string]int, len(claims))
	for _, c := range claims {
		if _, ok := inDegree[c.ID]; !ok {
			inDegree[c.ID] = 0
		}
		for _, dep := range c.DependsOn {
			inDegree[c.ID]++
			_ = dep
		}
	}
	// Recompute: each claim's in-degree = number of its dependencies.
	for _, c := range claims {
		inDegree[c.ID] = len(c.DependsOn)
	}

	queue := make([]string, 0, len(claims))
	for _, c := range claims {
		if inDegree[c.ID] == 0 {
			queue = append(queue, c.ID)
		}
	}

	var order []string
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		order = append(order, curr)
		for _, c := range claims {
			for _, dep := range c.DependsOn {
				if dep == curr {
					inDegree[c.ID]--
					if inDegree[c.ID] == 0 {
						queue = append(queue, c.ID)
					}
				}
			}
		}
	}
	if len(order) != len(claims) {
		return nil, fmt.Errorf("cycle detected")
	}
	return order, nil
}

// loadRawGraph loads the raw ProofGraph (with Checkers + Evidence lists).
func loadRawGraph(root string, useJSON bool) *ir.ProofGraph {
	graphPath := filepath.Join(root, config.DirName, config.GraphFile)
	data, err := os.ReadFile(graphPath)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "cannot read graph.json: "+err.Error())
	}
	pg, err := compile.Compile(data, compile.FormatJSON)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, "graph.json invalid: "+err.Error())
	}
	return pg
}

// findChecker returns the CheckerIdentity whose ID matches checkerPolicy.
func findChecker(pg *ir.ProofGraph, checkerPolicy string) (ir.CheckerIdentity, bool) {
	for _, ch := range pg.Checkers {
		if ch.ID == checkerPolicy {
			return ch, true
		}
	}
	return ir.CheckerIdentity{}, false
}

// findEvidence returns the EvidenceDescriptors whose digests match the refs.
func findEvidence(pg *ir.ProofGraph, refs []string) []ir.EvidenceDescriptor {
	refSet := make(map[string]struct{}, len(refs))
	for _, r := range refs {
		refSet[r] = struct{}{}
	}
	var out []ir.EvidenceDescriptor
	for _, ev := range pg.Evidence {
		if _, ok := refSet[ev.Digest]; ok {
			out = append(out, ev)
		}
	}
	return out
}
