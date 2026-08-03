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

func cmdInit(_ []string, _ bool) {
	fmt.Println("proofctl init: not yet implemented")
}

func cmdCompile(_ []string, _ bool) {
	fmt.Println("proofctl compile: not yet implemented")
}

func cmdCheck(_ []string, _ bool) {
	fmt.Println("proofctl check: not yet implemented")
}

func cmdVerify(_ []string, _ bool) {
	fmt.Println("proofctl verify: not yet implemented")
}

func cmdExplain(_ []string, _ bool) {
	fmt.Println("proofctl explain: not yet implemented")
}

func cmdGraph(_ []string, _ bool) {
	fmt.Println("proofctl graph: not yet implemented")
}

func cmdFrontier(_ []string, _ bool) {
	fmt.Println("proofctl frontier: not yet implemented")
}

func cmdImpact(_ []string, _ bool) {
	fmt.Println("proofctl impact: not yet implemented")
}

func cmdCache(_ []string, _ bool) {
	fmt.Println("proofctl cache: not yet implemented")
}

func cmdRelease(_ []string, _ bool) {
	fmt.Println("proofctl release: not yet implemented")
}

func cmdStatus(_ []string, useJSON bool) {
	type statusOutput struct {
		CertifiedRadius interface{} `json:"certified_radius"`
	}
	out := statusOutput{CertifiedRadius: nil}
	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}
	fmt.Println(`{"certified_radius": null}`)
}
