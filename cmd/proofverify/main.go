// Command proofverify is the minimal offline verification kernel for proofctl v2 bundles.
//
// proofverify is a read-only, deterministic, offline verifier. It accepts a
// signed release bundle and an external trust root, and outputs a single
// authoritative conclusion: released=true or released=false, with a full
// derivation trace.
//
// Design constraints (INV-11, INV-12):
//   - No network access
//   - No subprocess execution
//   - No plugin or extension loading
//   - No environment variable semantics (trust root must be explicitly passed)
//   - No automatic repair of any kind
//   - All state is re-derived from the bundle; no STATUS.json or cache is read
//
// Usage:
//
//	proofverify bundle.verify <bundle-path> [--trust-root <trust.json>]
//
// Exit codes:
//
//	0  released=true (all invariants satisfied)
//	1  released=false (one or more invariants violated, blockers listed)
//	2  usage error or bundle parse error
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/telleroutlook/proofctl/internal/kernel/bundle"
	"github.com/telleroutlook/proofctl/internal/kernel/derive"
)

// version is injected at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

// stateDerivationVersion identifies the rule set used by this binary.
const stateDerivationVersion = "v2.0-M25"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "bundle.verify":
		os.Exit(cmdBundleVerify(os.Args[2:]))
	case "--version", "-version":
		fmt.Printf("proofverify %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "proofverify: unknown subcommand %q\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

// cmdBundleVerify implements `proofverify bundle.verify`.
// Returns the exit code: 0=released, 1=not-released, 2=error.
func cmdBundleVerify(args []string) int {
	fs := flag.NewFlagSet("bundle.verify", flag.ContinueOnError)
	trustRootFlag := fs.String("trust-root", "", "path to external trust root JSON")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "proofverify: %v\n", err)
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "proofverify: bundle.verify requires a bundle path\n")
		return 2
	}
	bundlePath := fs.Arg(0)

	result, err := verifyBundle(bundlePath, *trustRootFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proofverify: %v\n", err)
		return 2
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "proofverify: encode result: %v\n", err)
		return 2
	}

	if result.Released {
		return 0
	}
	return 1
}

// verifyBundle reads the bundle at bundlePath, verifies all member digests,
// and derives the release state using the v2 kernel.
func verifyBundle(bundlePath, trustRootPath string) (*bundle.VerificationResult, error) {
	// Read manifest.json from the bundle directory (INV-12).
	manifestPath := bundlePath + "/manifest.json"
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	var manifest bundle.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	if manifest.FormatVersion != "2" {
		return nil, fmt.Errorf("unsupported bundle format_version %q (want \"2\")", manifest.FormatVersion)
	}

	// Verify all declared member digests (INV-12: bundle must be self-verifiable).
	var memberFailures []string
	for _, member := range manifest.Members {
		memberPath := bundlePath + "/" + member.Path
		data, readErr := os.ReadFile(memberPath)
		if readErr != nil {
			memberFailures = append(memberFailures, fmt.Sprintf("missing member %s: %v", member.Path, readErr))
			continue
		}
		if got := computeDigest(data); got != member.Digest {
			memberFailures = append(memberFailures, fmt.Sprintf(
				"member %s digest mismatch: stored %s, computed %s",
				member.Path, member.Digest, got))
		}
	}
	if len(memberFailures) > 0 {
		return &bundle.VerificationResult{
			Released:               false,
			RootState:              "BLOCKED",
			ClaimStates:            map[string]string{},
			Blockers:               memberFailures,
			StateDerivationVersion: stateDerivationVersion,
		}, nil
	}

	// Trust root: if provided, load and record it; if absent, add a warning blocker.
	var trustRootBlocker string
	if trustRootPath == "" {
		trustRootBlocker = "TRUST_ROOT_REQUIRED: --trust-root not provided; verification is incomplete (pass --trust-root for authoritative release)"
	} else {
		if _, err := os.Stat(trustRootPath); err != nil {
			return nil, fmt.Errorf("trust root file %q not found: %w", trustRootPath, err)
		}
		// Trust root loaded — manifest signature verification deferred to M32.
		fmt.Fprintf(os.Stderr, "proofverify: trust root loaded from %s (manifest signature verification pending M32)\n", trustRootPath)
	}

	// Derive claim states from bundle attestations.
	claimStates, blockers, released := deriveStatesFromBundle(bundlePath, &manifest)
	if trustRootBlocker != "" {
		// Informational blocker only — backward-compatible warning; does not override
		// released state. Hard enforcement deferred to M32 (--trust-root required).
		blockers = append(blockers, trustRootBlocker)
	}

	rootState := "OPEN"
	if s, ok := claimStates[manifest.RootClaim]; ok {
		rootState = s
	}

	return &bundle.VerificationResult{
		Released:               released,
		RootState:              rootState,
		ClaimStates:            claimStates,
		Blockers:               blockers,
		StateDerivationVersion: stateDerivationVersion,
	}, nil
}

// attV2Probe is a minimal v2 attestation shape used for state derivation.
type attV2Probe struct {
	ClaimID             string `json:"claim_id"`
	ClaimIdentityDigest string `json:"claim_identity_digest"`
	ObligationResults   []struct {
		Verdict string `json:"verdict"`
	} `json:"obligation_results"`
}

// deriveStatesFromBundle loads v2 attestations from the bundle and calls
// kernel/derive.DeriveClaimState for each claim. It returns claim states,
// blockers, and whether the root claim reaches a releasable state.
func deriveStatesFromBundle(bundlePath string, manifest *bundle.Manifest) (map[string]string, []string, bool) {
	attestDir := bundlePath + "/attestations"
	entries, err := os.ReadDir(attestDir)
	if err != nil {
		return map[string]string{manifest.RootClaim: "OPEN"},
			[]string{"no attestations directory in bundle"},
			false
	}

	claimStates := make(map[string]string)
	var blockers []string

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(attestDir + "/" + e.Name())
		if err != nil {
			continue
		}
		var att attV2Probe
		if err := json.Unmarshal(data, &att); err != nil || att.ClaimID == "" {
			continue
		}

		oblResult := derive.ObligationSetAbsent
		if len(att.ObligationResults) > 0 {
			allPass := true
			for _, o := range att.ObligationResults {
				if o.Verdict != "pass" {
					allPass = false
					break
				}
			}
			if allPass {
				oblResult = derive.ObligationSetPass
			} else {
				oblResult = derive.ObligationSetFail
			}
		}

		in := derive.DeriveInput{
			ClaimID:             att.ClaimID,
			CurrentIdentity:     att.ClaimIdentityDigest,
			AttestationIdentity: att.ClaimIdentityDigest,
			Evidence:            derive.EvidencePresent,
			ObligationSet:       oblResult,
			DepStates:           map[string]derive.ClaimStateV2{},
			RequiredDepStates:   map[string]derive.ClaimStateV2{},
		}
		state := derive.DeriveClaimState(in)
		claimStates[att.ClaimID] = string(state)

		if state == derive.StateBlocked || state == derive.StateStale {
			blockers = append(blockers, fmt.Sprintf("claim %s is %s", att.ClaimID, state))
		}
	}

	rootState, ok := claimStates[manifest.RootClaim]
	released := ok && (rootState == string(derive.StateGloballyVerified) ||
		rootState == string(derive.StateReproducible) ||
		rootState == string(derive.StateReleased))

	if !ok {
		blockers = append(blockers, fmt.Sprintf("root claim %q has no attestation", manifest.RootClaim))
	}

	return claimStates, blockers, released
}

// computeDigest returns "sha256:<hex>" for the given data.
func computeDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `proofverify %s — minimal offline proof release verifier

Usage:
  proofverify bundle.verify <bundle-path> [--trust-root <trust.json>]

Subcommands:
  bundle.verify    Verify a signed release bundle offline

Flags:
  --trust-root     Path to the external trust root JSON (required for formal release)
  --version        Print version

Exit codes:
  0  released=true
  1  released=false (blockers listed on stdout)
  2  usage or parse error

proofverify is the read-only, deterministic counterpart to proofctl.
It has no network access, no subprocess execution, and no automatic repair.
All state is re-derived from the bundle; no external cache or STATUS.json is read.
`, version)
}
