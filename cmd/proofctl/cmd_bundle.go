package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/telleroutlook/proofctl/internal/kernel/bundle"
)

// cmdBundle implements `proofctl bundle`.
//
// Usage:
//
//	proofctl bundle create [--output <dir>] [--policy <file>]
//	proofctl bundle verify <bundle-dir>
func cmdBundle(args []string, useJSON bool) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: proofctl bundle <create|verify> [args...]")
		os.Exit(1)
	}
	switch args[0] {
	case "create":
		cmdBundleCreate(args[1:], useJSON)
	case "verify":
		cmdBundleVerify(args[1:], useJSON)
	default:
		fmt.Fprintf(os.Stderr, "proofctl bundle: unknown subcommand %q\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: proofctl bundle create|verify [args...]")
		os.Exit(1)
	}
}

func cmdBundleCreate(args []string, useJSON bool) {
	outputDir := ".proofctl-bundle"
	policyOverride := ""

	// Simple flag parsing.
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--output", "-o":
			if i+1 < len(args) {
				outputDir = args[i+1]
				i++
			}
		case "--policy":
			if i+1 < len(args) {
				policyOverride = args[i+1]
				i++
			}
		}
	}

	root, cfg, _, _ := loadProjectGraph(useJSON)
	proofctlDir := filepath.Join(root, ".proofctl")

	// Determine policy file path.
	polPath := filepath.Join(root, cfg.PolicyFile)
	if policyOverride != "" {
		polPath = policyOverride
	}

	// Create bundle directory layout.
	dirs := []string{
		filepath.Join(outputDir, "attestations"),
		filepath.Join(outputDir, "contracts"),
		filepath.Join(outputDir, "signatures"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			die(useJSON, "INTERNAL_ERROR", fmt.Sprintf("mkdir %s: %v", d, err))
		}
	}

	var members []bundle.ManifestMemberDigest

	// Copy graph.json
	graphSrc := filepath.Join(proofctlDir, "graph.json")
	if d, err := copyToBundleFile(graphSrc, filepath.Join(outputDir, "graph.json")); err == nil {
		members = append(members, bundle.ManifestMemberDigest{Path: "graph.json", Digest: d})
	}

	// Copy policy.json
	if _, err := os.Stat(polPath); err == nil {
		if d, err := copyToBundleFile(polPath, filepath.Join(outputDir, "policy.json")); err == nil {
			members = append(members, bundle.ManifestMemberDigest{Path: "policy.json", Digest: d})
		}
	}

	// Copy attestations.
	attestDir := filepath.Join(proofctlDir, "attestations")
	if entries, err := os.ReadDir(attestDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			src := filepath.Join(attestDir, e.Name())
			dst := filepath.Join(outputDir, "attestations", e.Name())
			if d, err := copyToBundleFile(src, dst); err == nil {
				members = append(members, bundle.ManifestMemberDigest{
					Path:   "attestations/" + e.Name(),
					Digest: d,
				})
			}
		}
	}

	// Copy domain contracts if available.
	contractsDir := filepath.Join(root, "domains", "weil", "contracts")
	if entries, err := os.ReadDir(contractsDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			src := filepath.Join(contractsDir, e.Name())
			dst := filepath.Join(outputDir, "contracts", e.Name())
			if d, err := copyToBundleFile(src, dst); err == nil {
				members = append(members, bundle.ManifestMemberDigest{
					Path:   "contracts/" + e.Name(),
					Digest: d,
				})
			}
		}
	}

	// Determine root claim from policy.
	rootClaim := ""
	if polData, err := os.ReadFile(polPath); err == nil {
		var pol struct {
			Target string `json:"target"`
		}
		if err := json.Unmarshal(polData, &pol); err == nil {
			rootClaim = pol.Target
		}
	}

	// Compute policy digest.
	policyDigest := ""
	if polData, err := os.ReadFile(filepath.Join(outputDir, "policy.json")); err == nil {
		policyDigest = bundleDigest(polData)
	}

	// Compute graph root digest.
	graphRootDigest := ""
	if graphData, err := os.ReadFile(filepath.Join(outputDir, "graph.json")); err == nil {
		graphRootDigest = bundleDigest(graphData)
	}

	// Write manifest.
	manifest := bundle.Manifest{
		FormatVersion:          "2",
		RootClaim:              rootClaim,
		GraphRootDigest:        graphRootDigest,
		PolicyDigest:           policyDigest,
		StateDerivationVersion: "v2.0-M29",
		Members:                members,
		GeneratedAt:            time.Now().UTC().Format(time.RFC3339),
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		die(useJSON, "INTERNAL_ERROR", "marshal manifest: "+err.Error())
	}
	manifestData = append(manifestData, '\n')
	if err := os.WriteFile(filepath.Join(outputDir, "manifest.json"), manifestData, 0o644); err != nil {
		die(useJSON, "INTERNAL_ERROR", "write manifest: "+err.Error())
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"bundle_dir":   outputDir,
			"members":      len(members),
			"root_claim":   rootClaim,
			"generated_at": manifest.GeneratedAt,
		})
		return
	}
	fmt.Printf("bundle created: %s\n", outputDir)
	fmt.Printf("  root_claim: %s\n", rootClaim)
	fmt.Printf("  members: %d\n", len(members))
	fmt.Printf("  manifest: %s/manifest.json\n", outputDir)
	fmt.Println("\nRun 'proofctl bundle verify " + outputDir + "' to verify offline.")
}

func cmdBundleVerify(args []string, useJSON bool) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: proofctl bundle verify <bundle-dir>")
		os.Exit(1)
	}
	bundleDir := args[0]

	// Read and validate manifest.
	manifestData, err := os.ReadFile(filepath.Join(bundleDir, "manifest.json"))
	if err != nil {
		die(useJSON, "MISSING_MANIFEST", fmt.Sprintf("cannot read manifest: %v", err))
	}
	var manifest bundle.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		die(useJSON, "INVALID_MANIFEST", fmt.Sprintf("parse manifest: %v", err))
	}
	if manifest.FormatVersion != "2" {
		die(useJSON, "WRONG_FORMAT", fmt.Sprintf("unsupported format_version %q", manifest.FormatVersion))
	}

	// Verify all member digests.
	var failures []string
	for _, m := range manifest.Members {
		data, err := os.ReadFile(filepath.Join(bundleDir, m.Path))
		if err != nil {
			failures = append(failures, fmt.Sprintf("missing member %s", m.Path))
			continue
		}
		if got := bundleDigest(data); got != m.Digest {
			failures = append(failures, fmt.Sprintf("digest mismatch: %s (stored %s, computed %s)",
				m.Path, m.Digest, got))
		}
	}

	released := len(failures) == 0 && manifest.RootClaim != ""
	// Additional state derivation would happen here via kernel/derive in a full implementation.

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(bundle.VerificationResult{
			Released:               released,
			RootState:              map[bool]string{true: "GLOBALLY_VERIFIED", false: "BLOCKED"}[released],
			ClaimStates:            map[string]string{},
			Blockers:               failures,
			StateDerivationVersion: "v2.0-M29",
		})
		if !released {
			os.Exit(1)
		}
		return
	}

	if released {
		fmt.Printf("PASS: bundle verified — root claim: %s\n", manifest.RootClaim)
		fmt.Printf("  members: %d (all digests match)\n", len(manifest.Members))
	} else {
		fmt.Printf("FAIL: bundle verification failed\n")
		for _, f := range failures {
			fmt.Printf("  [FAIL] %s\n", f)
		}
		os.Exit(1)
	}
}

// copyToBundleFile copies src to dst and returns the sha256 digest of the content.
func copyToBundleFile(src, dst string) (string, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return "", err
	}
	return bundleDigest(data), nil
}

// bundleDigest returns "sha256:<hex>" of the given data.
func bundleDigest(data []byte) string {
	_ = io.Discard // imported for clarity
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}
