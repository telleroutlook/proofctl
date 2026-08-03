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

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/compile"
	"github.com/telleroutlook/proofctl/internal/config"
	"github.com/telleroutlook/proofctl/internal/dag"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
	"github.com/telleroutlook/proofctl/internal/release"
	"github.com/telleroutlook/proofctl/internal/status"
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
func cmdCompile(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl compile <file>")
	}
	srcFile := args[0]
	data, err := os.ReadFile(srcFile)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, "cannot read source file: "+err.Error())
	}

	pg, err := compile.Compile(data, compile.FormatJSON)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	// Build and validate DAG.
	g := dag.New()
	for i := range pg.Claims {
		if err := g.AddClaim(&pg.Claims[i]); err != nil {
			die(useJSON, errors.CodeDuplicateID, err.Error())
		}
	}
	if err := g.Validate(); err != nil {
		die(useJSON, errors.CodeCycleDetected, err.Error())
	}

	// Find project root to write graph.json.
	cwd, err := os.Getwd()
	if err != nil {
		die(useJSON, errors.CodeInternalError, err.Error())
	}
	root, err := config.Find(cwd)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	outPath := filepath.Join(root, config.DirName, config.GraphFile)
	out, _ := json.MarshalIndent(pg, "", "  ")
	out = append(out, '\n')
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		die(useJSON, errors.CodeInternalError, "cannot write graph.json: "+err.Error())
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(map[string]any{"compiled": len(pg.Claims), "output": outPath})
	} else {
		fmt.Printf("Compiled %d claims.\n", len(pg.Claims))
	}
}

// cmdStatus implements the status subcommand.
func cmdStatus(_ []string, useJSON bool) {
	_, _, g, attestations := loadProjectGraph(useJSON)

	statuses := status.Compute(g, attestations)

	if useJSON {
		claimsMap := make(map[string]string, len(statuses))
		for id, s := range statuses {
			claimsMap[id] = string(s)
		}
		type statusOutput struct {
			Claims          map[string]string `json:"claims"`
			CertifiedRadius interface{}       `json:"certified_radius"`
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(statusOutput{Claims: claimsMap, CertifiedRadius: nil})
		return
	}

	// Human output: sorted table.
	ids := make([]string, 0, len(statuses))
	for id := range statuses {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var accepted, open, blocked, rejected int
	for _, id := range ids {
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
		fmt.Printf("%-40s %s\n", id, s)
	}
	fmt.Printf("\naccepted=%d  open=%d  blocked=%d  rejected=%d\n", accepted, open, blocked, rejected)
}

// cmdGraph implements the graph subcommand.
func cmdGraph(args []string, useJSON bool) {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	targetFlag := fs.String("target", "", "show closure for @claim-id")
	_ = fs.Parse(args)

	_, _, g, _ := loadProjectGraph(useJSON)

	target := strings.TrimPrefix(*targetFlag, "@")

	type claimNode struct {
		ID        string   `json:"id"`
		Kind      string   `json:"kind"`
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
					nodes = append(nodes, claimNode{ID: c.ID, Kind: c.Kind, DependsOn: c.DependsOn})
				}
			}
		} else {
			for _, c := range claims {
				nodes = append(nodes, claimNode{ID: c.ID, Kind: c.Kind, DependsOn: c.DependsOn})
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
			deps = "(none)"
		}
		fmt.Printf("%s [%s] -> %s\n", c.ID, c.Kind, deps)
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
			ID        string          `json:"id"`
			Kind      string          `json:"kind"`
			Status    string          `json:"status"`
			Assurance string          `json:"assurance,omitempty"`
			Statement ir.Statement    `json:"statement"`
			DependsOn []string        `json:"depends_on"`
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
			out.Attestation = att
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	fmt.Printf("Claim:    %s\n", c.ID)
	fmt.Printf("Kind:     %s\n", c.Kind)
	fmt.Printf("Status:   %s\n", claimStatus)
	fmt.Printf("Statement: %s\n", c.Statement.Text)
	if len(c.DependsOn) > 0 {
		fmt.Printf("Depends on: %s\n", strings.Join(c.DependsOn, ", "))
	}
	if att != nil {
		fmt.Printf("Assurance: %s\n", att.Assurance)
		if att.BlockReason != "" {
			fmt.Printf("Block reason: %s\n", att.BlockReason)
		}
	}
	if claimStatus == ir.StatusBlocked {
		// Find blocking deps.
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
		Pass      bool     `json:"pass"`
		Blockers  []string `json:"blockers"`
		Released  bool     `json:"released"`
	}

	if *dryRunFlag {
		pass, blockers := gate.DryRun(g, attestations, pol)
		if useJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(releaseOutput{Pass: pass, Blockers: blockers, Released: false})
			return
		}
		if pass {
			fmt.Println("PASS: release gate passed (dry run)")
		} else {
			fmt.Println("FAIL: release gate failed (dry run)")
			for _, b := range blockers {
				fmt.Printf("  - %s\n", b)
			}
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
		_ = enc.Encode(releaseOutput{Pass: pass, Blockers: blockers, Released: pass})
		return
	}

	if pass {
		fmt.Println("PASS: release gate passed")
	} else {
		fmt.Println("FAIL: release gate failed")
		for _, b := range blockers {
			fmt.Printf("  - %s\n", b)
		}
	}
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

// cmdVerify implements the verify subcommand (not yet implemented).
func cmdVerify(_ []string, useJSON bool) {
	if useJSON {
		enc := json.NewEncoder(os.Stderr)
		_ = enc.Encode(errors.New(errors.CodeNotImplemented, "verify subcommand is not yet implemented"))
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "error: verify subcommand is not yet implemented")
	os.Exit(1)
}
