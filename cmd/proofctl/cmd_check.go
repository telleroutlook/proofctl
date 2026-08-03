package main

import (
	"encoding/json"
	"fmt"
	"os"

	errors "github.com/telleroutlook/proofctl/internal/errors"
)

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
