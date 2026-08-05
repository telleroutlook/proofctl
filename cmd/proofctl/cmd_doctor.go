package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/telleroutlook/proofctl/internal/compile"
	"github.com/telleroutlook/proofctl/internal/config"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// doctorCheck is a single environment check result.
type doctorCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Warn   bool   `json:"warn,omitempty"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

func cmdDoctor(args []string, useJSON bool) {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		die(useJSON, "invalid-input", err.Error())
	}

	var checks []doctorCheck

	// 1. proofctl in PATH
	checks = append(checks, checkProofctlInPath())

	// 2. .proofctl/ project found
	cwd, _ := os.Getwd()
	root, projectErr := config.Find(cwd)
	checks = append(checks, checkProjectFound(root, projectErr))

	// 3–7 require a project root; skip with a warning if not found.
	if projectErr == nil {
		checks = append(checks, checkBridgeCheckerEnv())
		checks = append(checks, checkBridgeCheckerExecutable())
		checks = append(checks, checkProofctlAdaptersEnv(root))
		checks = append(checks, checkCheckerPinned(root))
		checks = append(checks, checkCASNonEmpty(root))
		checks = append(checks, checkScriptedRuntime(root))
	}

	allOK := true
	for _, c := range checks {
		if !c.OK {
			allOK = false
		}
	}

	if useJSON {
		type jsonOut struct {
			Checks []doctorCheck `json:"checks"`
			OK     bool          `json:"ok"`
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(jsonOut{Checks: checks, OK: allOK})
	} else {
		for _, c := range checks {
			if c.OK && c.Warn {
				fmt.Printf("⚠ %s\n", c.Detail)
				if c.Fix != "" {
					fmt.Printf("  → %s\n", c.Fix)
				}
			} else if c.OK {
				fmt.Printf("✓ %s\n", c.Detail)
			} else {
				fmt.Printf("✗ %s\n", c.Detail)
				if c.Fix != "" {
					fmt.Printf("  → %s\n", c.Fix)
				}
			}
		}
	}

	if !allOK {
		os.Exit(1)
	}
}

func checkProofctlInPath() doctorCheck {
	path, err := exec.LookPath("proofctl")
	if err != nil {
		return doctorCheck{
			Name:   "proofctl-in-path",
			OK:     true,
			Warn:   true,
			Detail: "proofctl not found in PATH (binary not yet installed system-wide)",
			Fix:    "add the directory containing the proofctl binary to your PATH",
		}
	}
	return doctorCheck{
		Name:   "proofctl-in-path",
		OK:     true,
		Detail: fmt.Sprintf("proofctl in PATH (%s)", path),
	}
}

func checkProjectFound(root string, err error) doctorCheck {
	if err != nil {
		return doctorCheck{
			Name:   "project-found",
			OK:     false,
			Detail: "not in a proofctl project (.proofctl/ not found)",
			Fix:    "run 'proofctl init' in your project directory",
		}
	}
	return doctorCheck{
		Name:   "project-found",
		OK:     true,
		Detail: fmt.Sprintf(".proofctl/ project found (%s)", root),
	}
}

func checkBridgeCheckerEnv() doctorCheck {
	val := os.Getenv("BRIDGE_CHECKER")
	if val == "" {
		return doctorCheck{
			Name:   "bridge-checker-set",
			OK:     false,
			Detail: "BRIDGE_CHECKER not set",
			Fix:    `export BRIDGE_CHECKER="python3 checker/check_certificate.py"`,
		}
	}
	return doctorCheck{
		Name:   "bridge-checker-set",
		OK:     true,
		Detail: fmt.Sprintf("BRIDGE_CHECKER set (%s)", val),
	}
}

func checkBridgeCheckerExecutable() doctorCheck {
	val := os.Getenv("BRIDGE_CHECKER")
	if val == "" {
		// Already reported by checkBridgeCheckerEnv.
		return doctorCheck{
			Name:   "bridge-checker-executable",
			OK:     true,
			Detail: "BRIDGE_CHECKER executable check skipped (not set)",
		}
	}
	// Extract the first word as the executable.
	parts := strings.Fields(val)
	exe := parts[0]

	// For bare names (e.g. "python3"), resolve via PATH; for paths, check directly.
	resolvedExe := exe
	if !strings.Contains(exe, "/") {
		if found, err := exec.LookPath(exe); err == nil {
			resolvedExe = found
		} else {
			return doctorCheck{
				Name:   "bridge-checker-executable",
				OK:     false,
				Detail: fmt.Sprintf("BRIDGE_CHECKER executable not found in PATH: %s", exe),
				Fix:    fmt.Sprintf("install %s or use an absolute path in BRIDGE_CHECKER", exe),
			}
		}
	}

	info, err := os.Stat(resolvedExe)
	if err != nil {
		return doctorCheck{
			Name:   "bridge-checker-executable",
			OK:     false,
			Detail: fmt.Sprintf("BRIDGE_CHECKER path not found: %s", exe),
			Fix:    "ensure the BRIDGE_CHECKER path exists and is executable",
		}
	}
	if info.Mode()&0o111 == 0 {
		return doctorCheck{
			Name:   "bridge-checker-executable",
			OK:     false,
			Detail: fmt.Sprintf("BRIDGE_CHECKER not executable: %s", resolvedExe),
			Fix:    fmt.Sprintf("chmod +x %s", resolvedExe),
		}
	}
	return doctorCheck{
		Name:   "bridge-checker-executable",
		OK:     true,
		Detail: fmt.Sprintf("BRIDGE_CHECKER executable (%s)", resolvedExe),
	}
}

// checkProofctlAdaptersEnv checks whether PROOFCTL_ADAPTERS is set when the
// compiled graph.json references ${PROOFCTL_ADAPTERS} in any checker cmd.
func checkProofctlAdaptersEnv(root string) doctorCheck {
	needsVar := graphUsesAdaptersVar(root)
	val := os.Getenv("PROOFCTL_ADAPTERS")
	if needsVar && val == "" {
		return doctorCheck{
			Name:   "proofctl-adapters-set",
			OK:     false,
			Detail: "PROOFCTL_ADAPTERS not set (required by graph.json checkers)",
			Fix:    "export PROOFCTL_ADAPTERS=/path/to/proofctl/adapters",
		}
	}
	if val != "" {
		return doctorCheck{
			Name:   "proofctl-adapters-set",
			OK:     true,
			Detail: fmt.Sprintf("PROOFCTL_ADAPTERS set (%s)", val),
		}
	}
	return doctorCheck{
		Name:   "proofctl-adapters-set",
		OK:     true,
		Detail: "PROOFCTL_ADAPTERS not required by this project",
	}
}

// graphUsesAdaptersVar reports whether the compiled graph.json references
// ${PROOFCTL_ADAPTERS} in any checker Runtime.Cmd entry.
func graphUsesAdaptersVar(root string) bool {
	pg := loadCompiledGraph(root)
	if pg == nil {
		return false
	}
	for _, ch := range pg.Checkers {
		for _, part := range ch.Runtime.Cmd {
			if strings.Contains(part, "${PROOFCTL_ADAPTERS}") {
				return true
			}
		}
	}
	return false
}

// checkCheckerPinned verifies that no checker in graph.json has an all-zero digest.
func checkCheckerPinned(root string) doctorCheck {
	pg := loadCompiledGraph(root)
	if pg == nil {
		return doctorCheck{
			Name:   "checker-pinned",
			OK:     true,
			Detail: "checker pin check skipped (no compiled graph.json)",
		}
	}
	zeroDigest := "sha256:" + strings.Repeat("0", 64)
	var unpinned []string
	for _, ch := range pg.Checkers {
		if ch.CheckerDigest == "" || ch.CheckerDigest == zeroDigest {
			unpinned = append(unpinned, ch.ID)
		}
	}
	if len(unpinned) > 0 {
		return doctorCheck{
			Name:   "checker-pinned",
			OK:     false,
			Detail: fmt.Sprintf("checker not pinned for %d checker(s): %s", len(unpinned), strings.Join(unpinned, ", ")),
			Fix:    "run 'proofctl pin checker --cmd \"<interpreter> <script>\"'",
		}
	}
	return doctorCheck{
		Name:   "checker-pinned",
		OK:     true,
		Detail: "all checkers pinned",
	}
}

// checkCASNonEmpty checks whether the CAS directory has at least one entry,
// but only if graph.json declares any evidence.
func checkCASNonEmpty(root string) doctorCheck {
	pg := loadCompiledGraph(root)
	if pg == nil || len(pg.Evidence) == 0 {
		return doctorCheck{
			Name:   "cas-non-empty",
			OK:     true,
			Detail: "CAS check skipped (no evidence declared in graph.json)",
		}
	}

	casDir := filepath.Join(root, config.DirName, config.CASDir)
	entries, err := os.ReadDir(casDir)
	if err != nil || len(entries) == 0 {
		return doctorCheck{
			Name:   "cas-non-empty",
			OK:     false,
			Detail: "CAS is empty — no evidence imported yet",
			Fix:    "run 'proofctl cas import <cert-file>' for each evidence file",
		}
	}
	return doctorCheck{
		Name:   "cas-non-empty",
		OK:     true,
		Detail: fmt.Sprintf("CAS has %d entry/entries", len(entries)),
	}
}

// loadCompiledGraph reads and parses .proofctl/graph.json, returning nil on any error.
func loadCompiledGraph(root string) *ir.ProofGraph {
	data, err := os.ReadFile(filepath.Join(root, config.DirName, config.GraphFile))
	if err != nil {
		return nil
	}
	pg, err := compile.Compile(data, compile.FormatJSON)
	if err != nil {
		return nil
	}
	return pg
}

// checkScriptedRuntime warns when any checker uses runtime kind "scripted".
// scripted checkers run as plain host processes; cross-machine reproducibility
// depends on the environment rather than a pinned container image.
func checkScriptedRuntime(root string) doctorCheck {
	pg := loadCompiledGraph(root)
	if pg == nil {
		return doctorCheck{
			Name:   "scripted-runtime",
			OK:     true,
			Detail: "scripted-runtime check skipped (no compiled graph.json)",
		}
	}
	var scripted []string
	for _, ch := range pg.Checkers {
		if ch.Runtime.Kind == "scripted" {
			scripted = append(scripted, ch.ID)
		}
	}
	if len(scripted) > 0 {
		return doctorCheck{
			Name:   "scripted-runtime",
			OK:     true,
			Warn:   true,
			Detail: fmt.Sprintf("runtime 'scripted' in use (%s): cross-machine reproducibility depends on host environment, not a pinned container", strings.Join(scripted, ", ")),
			Fix:    "consider 'isolated-oci' runtime for third-party independent verification",
		}
	}
	return doctorCheck{
		Name:   "scripted-runtime",
		OK:     true,
		Detail: "no scripted-runtime checkers",
	}
}
