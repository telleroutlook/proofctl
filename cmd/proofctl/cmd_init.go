package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/scaffold"
)

func cmdInit(args []string, useJSON bool) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	policyFlag := fs.String("policy", "", "path to policy file (relative to project root), e.g. policies/my-domain-v1.json")
	domainFlag := fs.String("domain", "", "scaffold a known domain (cap, lrat, qmd); sets policy and writes templates")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "cannot resolve path: "+err.Error())
	}

	// Resolve policy file: --domain wins over --policy if both given.
	policyFile := *policyFlag
	var dom scaffold.Domain
	if *domainFlag != "" {
		d, err := scaffold.Lookup(*domainFlag)
		if err != nil {
			die(useJSON, errors.CodeInvalidInput, err.Error())
		}
		dom = d
		if p := scaffold.PolicyFile(d); p != "" {
			policyFile = p
		}
	}

	if err := config.Init(abs, policyFile); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	policiesDir := filepath.Join(abs, "policies")
	if mkErr := os.MkdirAll(policiesDir, 0o755); mkErr != nil {
		die(useJSON, errors.CodeInternalError, "cannot create policies directory: "+mkErr.Error())
	}

	// Write domain scaffold files if --domain was given.
	if dom.Name != "" {
		if err := scaffold.Init(abs, dom); err != nil {
			die(useJSON, errors.CodeInternalError, err.Error())
		}
	}

	if useJSON {
		out := map[string]string{
			"initialized": abs,
		}
		if dom.Name != "" {
			out["domain"] = dom.Name
			out["note"] = fmt.Sprintf("domain %q scaffolded; edit graph.json and policies/%s-v1.json before running 'proofctl compile'", dom.Name, dom.Name)
		} else if policyFile != "" {
			out["note"] = fmt.Sprintf("policy set to %q; copy your policy file there before running 'proofctl release'", policyFile)
		} else {
			out["note"] = "set policy_file in .proofctl/config.json before running 'proofctl release'"
		}
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(out)
	} else {
		fmt.Printf("Initialized .proofctl in %s\n", abs)
		if dom.Name != "" {
			fmt.Printf("Domain:  %s — %s\n", dom.Name, dom.Description)
			fmt.Printf("Written: graph.json, policies/%s-v1.json", dom.Name)
			if dom.BridgeSrc != "" {
				fmt.Printf(", adapters/bridge.py")
			}
			fmt.Println()
			fmt.Println("Next:    edit graph.json to define your claims, then run 'proofctl compile --adapter json graph.json'")
		} else if policyFile != "" {
			fmt.Printf("Policy: %s\n", policyFile)
		} else {
			fmt.Println("Note: set policy_file in .proofctl/config.json before running 'proofctl release'")
		}
	}
}
