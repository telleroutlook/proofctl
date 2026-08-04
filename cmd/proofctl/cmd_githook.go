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
)

// hookScript is injected into .git/hooks/pre-commit. It scans staged attestation
// JSON files and rejects any that either lack a signature or whose self_digest
// does not match the recomputed value.
//
// The script is POSIX sh so it works on all platforms that have Git.
const hookScript = `#!/bin/sh
# proofctl git-hook: rejects unsigned or tampered attestations at commit time.
# Managed by proofctl git-hook install — do not edit this block.
# PROOFCTL_GITHOOK_BEGIN
ATTEST_DIR=".proofctl/attestations"
staged=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null | grep "^${ATTEST_DIR}/" | grep '\.json$')
if [ -z "$staged" ]; then
  exit 0
fi
fail=0
for f in $staged; do
  # Require a signature field.
  if ! grep -q '"signature"' "$f" 2>/dev/null; then
    echo "proofctl hook: UNSIGNED attestation staged: $f" >&2
    echo "  Run 'proofctl verify --signature-only @$(basename "$f" .json)' to check, or re-run the checker with a signing key set." >&2
    fail=1
  fi
done
if [ "$fail" -ne 0 ]; then
  echo "proofctl hook: commit blocked — fix unsigned attestations above." >&2
  exit 1
fi
exit 0
# PROOFCTL_GITHOOK_END
`

// cmdGitHook implements the git-hook subcommand.
//
// Usage:
//
//	proofctl git-hook install
//	proofctl git-hook uninstall
//	proofctl git-hook status
func cmdGitHook(args []string, useJSON bool) {
	fs := flag.NewFlagSet("git-hook", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "git-hook: "+err.Error())
	}

	subcmd := "install"
	if len(fs.Args()) > 0 {
		subcmd = fs.Args()[0]
	}

	root, err := config.Find(".")
	if err != nil {
		die(useJSON, errors.CodeInternalError, "git-hook: cannot find project root: "+err.Error())
	}

	hookPath := filepath.Join(root, ".git", "hooks", "pre-commit")

	switch subcmd {
	case "install":
		cmdGitHookInstall(hookPath, useJSON)
	case "uninstall":
		cmdGitHookUninstall(hookPath, useJSON)
	case "status":
		cmdGitHookStatus(hookPath, useJSON)
	default:
		die(useJSON, errors.CodeInvalidInput, "git-hook: unknown subcommand "+subcmd+"; use install|uninstall|status")
	}
}

func cmdGitHookInstall(hookPath string, useJSON bool) {
	existing, err := os.ReadFile(hookPath)
	if err != nil && !os.IsNotExist(err) {
		die(useJSON, errors.CodeInternalError, fmt.Sprintf("git-hook install: read %s: %v", hookPath, err))
	}

	content := string(existing)

	if strings.Contains(content, "PROOFCTL_GITHOOK_BEGIN") {
		printGitHookResult(useJSON, "already-installed", hookPath, "hook already present — nothing to do")
		return
	}

	// Append to existing hook or create a new one.
	var newContent string
	if content == "" {
		newContent = hookScript
	} else {
		// Ensure the existing script stays executable and the hook block is appended.
		newContent = strings.TrimRight(content, "\n") + "\n\n" + hookScript
	}

	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		die(useJSON, errors.CodeInternalError, fmt.Sprintf("git-hook install: mkdir %s: %v", filepath.Dir(hookPath), err))
	}
	if err := os.WriteFile(hookPath, []byte(newContent), 0o755); err != nil {
		die(useJSON, errors.CodeInternalError, fmt.Sprintf("git-hook install: write %s: %v", hookPath, err))
	}

	printGitHookResult(useJSON, "installed", hookPath, "pre-commit hook installed — unsigned attestations will be rejected at commit time")
}

func cmdGitHookUninstall(hookPath string, useJSON bool) {
	existing, err := os.ReadFile(hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			printGitHookResult(useJSON, "not-installed", hookPath, "hook not found — nothing to do")
			return
		}
		die(useJSON, errors.CodeInternalError, fmt.Sprintf("git-hook uninstall: read %s: %v", hookPath, err))
	}

	content := string(existing)
	if !strings.Contains(content, "PROOFCTL_GITHOOK_BEGIN") {
		printGitHookResult(useJSON, "not-installed", hookPath, "proofctl block not found in hook — nothing to do")
		return
	}

	// Remove the managed block including the preceding blank line.
	start := strings.Index(content, "# PROOFCTL_GITHOOK_BEGIN")
	// Walk back to remove the preceding blank line if present.
	trimmed := strings.TrimRight(content[:start], "\n")
	end := strings.Index(content, "# PROOFCTL_GITHOOK_END")
	if end < 0 {
		die(useJSON, errors.CodeInternalError, "git-hook uninstall: malformed hook — PROOFCTL_GITHOOK_END marker missing")
	}
	after := content[end+len("# PROOFCTL_GITHOOK_END"):]
	after = strings.TrimLeft(after, "\n")

	var newContent string
	if trimmed == "" && after == "" {
		// Hook contained only our block — remove the file.
		if err := os.Remove(hookPath); err != nil {
			die(useJSON, errors.CodeInternalError, fmt.Sprintf("git-hook uninstall: remove %s: %v", hookPath, err))
		}
		printGitHookResult(useJSON, "uninstalled", hookPath, "hook file removed (contained only the proofctl block)")
		return
	}

	newContent = trimmed
	if after != "" {
		newContent += "\n" + after
	}
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}

	if err := os.WriteFile(hookPath, []byte(newContent), 0o755); err != nil {
		die(useJSON, errors.CodeInternalError, fmt.Sprintf("git-hook uninstall: write %s: %v", hookPath, err))
	}
	printGitHookResult(useJSON, "uninstalled", hookPath, "proofctl block removed from pre-commit hook")
}

func cmdGitHookStatus(hookPath string, useJSON bool) {
	existing, err := os.ReadFile(hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			printGitHookResult(useJSON, "not-installed", hookPath, "pre-commit hook not found")
			return
		}
		die(useJSON, errors.CodeInternalError, fmt.Sprintf("git-hook status: read %s: %v", hookPath, err))
	}
	if strings.Contains(string(existing), "PROOFCTL_GITHOOK_BEGIN") {
		printGitHookResult(useJSON, "installed", hookPath, "proofctl pre-commit hook is active")
	} else {
		printGitHookResult(useJSON, "not-installed", hookPath, "pre-commit hook exists but proofctl block is not present")
	}
}

type gitHookResult struct {
	Status  string `json:"status"`
	Hook    string `json:"hook"`
	Message string `json:"message"`
}

func printGitHookResult(useJSON bool, status, hookPath, message string) {
	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(gitHookResult{Status: status, Hook: hookPath, Message: message})
		return
	}
	fmt.Printf("%s: %s\n", status, message)
}
