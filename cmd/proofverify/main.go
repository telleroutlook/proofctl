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
//
// TODO M25: Full implementation. This binary currently prints usage only.
package main

import (
	"fmt"
	"os"
)

// version is injected at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "bundle.verify":
		// TODO M25: implement bundle verification using internal/kernel
		fmt.Fprintf(os.Stderr, "proofverify %s: bundle.verify not yet implemented (M25)\n", version)
		fmt.Fprintf(os.Stderr, "This binary will become the minimal offline release verifier.\n")
		os.Exit(2)
	case "--version", "-version":
		fmt.Printf("proofverify %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "proofverify: unknown subcommand %q\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `proofverify %s — minimal offline proof release verifier

Usage:
  proofverify bundle.verify <bundle-path> [--trust-root <trust.json>]

Subcommands:
  bundle.verify    Verify a signed release bundle offline (TODO: M25)

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
