package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/telleroutlook/proofctl/internal/kernel/contract"
)

// cmdContract implements the `proofctl contract` subcommand.
//
// Usage:
//
//	proofctl contract lint <file.json>
func cmdContract(args []string, useJSON bool) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: proofctl contract lint <contract.json>")
		os.Exit(1)
	}
	switch args[0] {
	case "lint":
		cmdContractLint(args[1:], useJSON)
	default:
		fmt.Fprintf(os.Stderr, "proofctl contract: unknown subcommand %q\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: proofctl contract lint <contract.json>")
		os.Exit(1)
	}
}

func cmdContractLint(args []string, useJSON bool) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: proofctl contract lint <contract.json>")
		os.Exit(1)
	}
	path := args[0]

	data, err := os.ReadFile(path)
	if err != nil {
		if useJSON {
			printJSONError(fmt.Sprintf("cannot read contract file %q: %v", path, err))
		} else {
			fmt.Fprintf(os.Stderr, "error: cannot read %q: %v\n", path, err)
		}
		os.Exit(1)
	}

	var c contract.ContractV2
	if err := json.Unmarshal(data, &c); err != nil {
		if useJSON {
			printJSONError(fmt.Sprintf("invalid JSON in %q: %v", path, err))
		} else {
			fmt.Fprintf(os.Stderr, "error: invalid JSON in %q: %v\n", path, err)
		}
		os.Exit(1)
	}

	lintErrs := contract.LintContract(c)

	if useJSON {
		type lintOutput struct {
			File    string               `json:"file"`
			ClaimID string               `json:"claim_id,omitempty"`
			Pass    bool                 `json:"pass"`
			Errors  []contract.LintError `json:"errors"`
		}
		out := lintOutput{
			File:    path,
			ClaimID: c.ClaimID,
			Pass:    len(lintErrs) == 0,
			Errors:  lintErrs,
		}
		if out.Errors == nil {
			out.Errors = []contract.LintError{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		if len(lintErrs) > 0 {
			os.Exit(1)
		}
		return
	}

	if len(lintErrs) == 0 {
		fmt.Printf("contract lint: %s — OK (claim: %s)\n", path, c.ClaimID)
		return
	}

	fmt.Fprintf(os.Stderr, "contract lint: %s — %d error(s)\n", path, len(lintErrs))
	for _, e := range lintErrs {
		fmt.Fprintf(os.Stderr, "  [%s] %s: %s\n", e.Code, e.Field, e.Message)
	}
	os.Exit(1)
}

// printJSONError writes a minimal JSON error to stdout for --json mode.
func printJSONError(msg string) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]string{"error": msg})
}
