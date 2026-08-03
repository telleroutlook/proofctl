package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/signing"
)

// keysDir is the directory under .proofctl/ where keys are stored.
const keysDir = "keys"

func cmdKey(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl key <generate|list>")
	}
	switch args[0] {
	case "generate":
		cmdKeyGenerate(args[1:], useJSON)
	case "list":
		cmdKeyList(args[1:], useJSON)
	default:
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("key: unknown subcommand %q (want: generate, list)", args[0]))
	}
}

func cmdKeyGenerate(args []string, useJSON bool) {
	fs := flag.NewFlagSet("key generate", flag.ContinueOnError)
	nameFlag := fs.String("name", "default", "key name (stored as <name>.priv and <name>.pub)")
	outFlag := fs.String("out", "", "output directory (default: <project>/.proofctl/keys/)")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	var dir string
	var projectRoot string
	if *outFlag != "" {
		dir = *outFlag
		// Best-effort: find project root for .gitignore update; ignore if not in a project.
		cwd, _ := os.Getwd()
		projectRoot, _ = config.Find(cwd)
	} else {
		cwd, _ := os.Getwd()
		root, err := config.Find(cwd)
		if err != nil {
			die(useJSON, errors.CodeInvalidInput, err.Error())
		}
		projectRoot = root
		dir = filepath.Join(root, config.DirName, keysDir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		die(useJSON, errors.CodeInternalError, "key generate: mkdir keys: "+err.Error())
	}

	k, err := signing.GenerateKey()
	if err != nil {
		die(useJSON, errors.CodeInternalError, "key generate: "+err.Error())
	}

	privPath := filepath.Join(dir, *nameFlag+".priv")
	pubPath := filepath.Join(dir, *nameFlag+".pub")

	if err := k.SavePrivate(privPath); err != nil {
		die(useJSON, errors.CodeInternalError, "key generate: "+err.Error())
	}
	if err := k.SavePublic(pubPath); err != nil {
		die(useJSON, errors.CodeInternalError, "key generate: "+err.Error())
	}

	// Ensure .gitignore covers *.priv
	if projectRoot != "" {
		ensureGitignore(projectRoot, "*.priv")
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(map[string]string{
			"name":             *nameFlag,
			"fingerprint":      k.ID,
			"private_key_path": privPath,
			"public_key_path":  pubPath,
		})
	} else {
		fmt.Printf("Generated key %q\n", *nameFlag)
		fmt.Printf("  fingerprint: %s\n", k.ID)
		fmt.Printf("  private key: %s (mode 0600, not committed)\n", privPath)
		fmt.Printf("  public key:  %s\n", pubPath)
	}
}

func cmdKeyList(args []string, useJSON bool) {
	fs := flag.NewFlagSet("key list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	cwd, _ := os.Getwd()
	root, err := config.Find(cwd)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	dir := filepath.Join(root, config.DirName, keysDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if useJSON {
				fmt.Println("[]")
			} else {
				fmt.Println("no keys found — run 'proofctl key generate'")
			}
			return
		}
		die(useJSON, errors.CodeInternalError, "key list: "+err.Error())
	}

	type keyInfo struct {
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint"`
		PublicKey   string `json:"public_key_path"`
	}
	var keys []keyInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".pub")
		pubPath := filepath.Join(dir, e.Name())
		k, err := signing.LoadPublic(pubPath)
		if err != nil {
			continue
		}
		keys = append(keys, keyInfo{Name: name, Fingerprint: k.ID, PublicKey: pubPath})
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(keys)
	} else {
		if len(keys) == 0 {
			fmt.Println("no keys found — run 'proofctl key generate'")
			return
		}
		for _, ki := range keys {
			fmt.Printf("%-20s  %s  %s\n", ki.Name, ki.Fingerprint, ki.PublicKey)
		}
	}
}

// ensureGitignore adds pattern to <root>/.gitignore if not already present.
func ensureGitignore(root, pattern string) {
	path := filepath.Join(root, ".gitignore")
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), pattern) {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		_, _ = fmt.Fprintln(f)
	}
	_, _ = fmt.Fprintln(f, "# proofctl signing keys — private keys must not be committed")
	_, _ = fmt.Fprintln(f, ".proofctl/keys/"+pattern)
}
