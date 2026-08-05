// Package main implements the proofctl CLI.
//
// Subcommands:
//
//	init      Initialize a new proof graph project (--domain cap|lrat|qmd for scaffolding)
//	domains   List known domains (proofctl domains list)
//	env       Manage checker runtime environment (verify|snapshot)
//	replay    Cold-start generator+checker replay for a claim
//	compile   Compile a proof source file to ProofGraph IR
//	check     Run checkers for one or more claims
//	verify    Verify attestation integrity
//	explain   Explain the status of a claim
//	graph     Print the claim dependency graph
//	frontier  List the unresolved direct dependencies of a claim
//	impact    List claims that depend on a given claim
//	cache     Manage the checker result cache
//	cas       Manage the content-addressed store (import|list)
//	pin       Pin a checker binary digest and command (pin checker --cmd ...)
//	release   Run the release gate
//	status    Print the current proof graph status
//	snapshot  Write a point-in-time snapshot of claims + statuses
//	doctor    Check that the proofctl environment is ready
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/telleroutlook/proofctl/internal/compile"
	"github.com/telleroutlook/proofctl/internal/config"
	"github.com/telleroutlook/proofctl/internal/dag"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/policy"
	"github.com/telleroutlook/proofctl/internal/signing"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	// Auto-load .proofctl/env before parsing flags so env vars are available.
	autoLoadEnv()

	jsonFlag := flag.Bool("json", false, "output in JSON format")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *versionFlag {
		fmt.Println("proofctl", version)
		return
	}

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
	case "attest":
		cmdAttest(subargs, *jsonFlag)
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
	case "cas":
		cmdCas(subargs, *jsonFlag)
	case "pin":
		cmdPin(subargs, *jsonFlag)
	case "domains":
		cmdDomains(subargs, *jsonFlag)
	case "env":
		cmdEnv(subargs, *jsonFlag)
	case "replay":
		cmdReplay(subargs, *jsonFlag)
	case "release":
		cmdRelease(subargs, *jsonFlag)
	case "status":
		cmdStatus(subargs, *jsonFlag)
	case "snapshot":
		cmdSnapshot(subargs, *jsonFlag)
	case "doctor":
		cmdDoctor(subargs, *jsonFlag)
	case "key":
		cmdKey(subargs, *jsonFlag)
	case "export":
		cmdExport(subargs, *jsonFlag)
	case "contract":
		cmdContract(subargs, *jsonFlag)
	case "identity":
		cmdIdentity(subargs, *jsonFlag)
	case "mutate":
		cmdMutate(subargs, *jsonFlag)
	case "bundle":
		cmdBundle(subargs, *jsonFlag)
	case "git-hook":
		cmdGitHook(subargs, *jsonFlag)
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
  init      Initialize a new proof graph project (--domain cap|lrat|qmd)
  domains   List known domains (domains list)
  compile   Compile a proof source file to ProofGraph IR
  check     Run checker against CAS evidence for a claim (--all | --no-cache | --evidence <digest>)
  verify    Verify attestation integrity (--signature-only skips re-running the checker)
  attest    Record a manual attestation (--batch, diff, --force, --key)
  explain   Explain the status of a claim
  graph     Print the claim dependency graph (--dot, --mermaid)
  frontier  List unresolved direct dependencies of a claim
  impact    List claims that depend on a given claim
  cache     Manage the checker result cache (audit|invalidate [--all]|show-key)
  cas       Manage the content-addressed store (import|import-dir|list|gc [--yes])
  pin       Pin a checker binary digest and command (pin checker --cmd ...)
  env       Manage checker runtime environment (verify|snapshot|show)
  replay    Cold-start generator+checker replay (--batch, --skip-if-accepted)
  release   Run the release gate (--dry-run)
  snapshot  Write a point-in-time snapshot of claims + statuses (--diff)
  doctor    Check that the proofctl environment is ready (PATH, project, checker, CAS)
  key       Manage signing keys (generate|list)
  export    Export an accepted claim to a cross-domain format (--format lean)
  contract  Verify a Verification Contract v2 file (contract lint <file>)
  identity  Show the content identity closure of a claim (identity @claim)
  mutate    Run the mandatory mutation catalog (kill rate must be 100%)
  bundle    Manage release bundles (bundle create|verify)
  git-hook  Manage the pre-commit attestation guard (install|uninstall|status)
  status    Print the current proof graph status (--watch)

Flags:
  --json      Output in JSON format
  --version   Print version and exit`)
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

	graphFile := config.GraphFile
	if cfg.GraphSource != "" {
		graphFile = cfg.GraphSource
	}
	graphPath := filepath.Join(root, config.DirName, graphFile)
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
		// T-M31-2: for v2 attestations, verify self-digest integrity.
		if att.Checker.ProtocolVersion == 2 {
			if att.Signature != nil && att.Signature.Value != "" {
				keysDir := filepath.Join(root, config.DirName, "keys")
				if verifyErr := verifyAttestationSig(att, keysDir); verifyErr != nil {
					die(useJSON, errors.CodeInvalidInput,
						fmt.Sprintf("attestation %s: signature verification failed: %v", entry.Name(), verifyErr))
				}
			}
		}
		attestations[att.ClaimID] = att
	}
	return attestations
}

// loadPolicy reads and parses the policy file at path.
func loadPolicy(path string, useJSON bool) policy.ReleasePolicy {
	data, err := os.ReadFile(path)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("cannot read policy file %s: %v", path, err))
	}
	var pol policy.ReleasePolicy
	if err := json.Unmarshal(data, &pol); err != nil {
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("cannot parse policy file %s: %v", path, err))
	}
	return pol
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

// topoSort returns all claim IDs in topological order (dependencies before dependents).
func topoSort(g *dag.DAG) ([]string, error) {
	claims := g.Claims()
	inDegree := make(map[string]int, len(claims))
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

// verifyAttestationSig verifies the Ed25519 signature on a v2 attestation
// against public keys in keysDir. Returns nil if valid or if no matching key
// is found locally (key-not-found is allowed — key may not be local). Returns
// an error only on cryptographic verification failure.
func verifyAttestationSig(att *ir.Attestation, keysDir string) error {
	sig := att.Signature
	if sig == nil || sig.Value == "" {
		return nil
	}
	// Load all public keys and find the one matching the signature fingerprint.
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil // no keys dir — skip
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		key, loadErr := signing.LoadPublic(filepath.Join(keysDir, e.Name()))
		if loadErr != nil {
			continue
		}
		if key.ID != sig.PubkeyFingerprint {
			continue
		}
		// Found the matching key — perform cryptographic verification.
		sigObj := signing.Signature{
			PubkeyFingerprint: sig.PubkeyFingerprint,
			Algorithm:         sig.Algorithm,
			Value:             sig.Value,
		}
		return signing.Verify(key, att, sigObj)
	}
	// No local key with this fingerprint — cannot verify; allow (warn not error).
	return nil
}
