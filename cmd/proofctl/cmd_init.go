package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
)

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
	// Create the policies/ directory so users have a clear place to put policy files.
	policiesDir := filepath.Join(abs, "policies")
	if mkErr := os.MkdirAll(policiesDir, 0o755); mkErr != nil {
		die(useJSON, errors.CodeInternalError, "cannot create policies directory: "+mkErr.Error())
	}
	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(map[string]string{
			"initialized": abs,
			"note":        "copy your policy files to policies/ before running 'proofctl release'",
		})
	} else {
		fmt.Printf("Initialized .proofctl in %s\n", abs)
		fmt.Println("Note: copy your policy files to policies/ before running 'proofctl release'")
	}
}
