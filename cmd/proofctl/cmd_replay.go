package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// multiFlag is a repeatable string flag that collects all occurrences.
type multiFlag []string

func (f *multiFlag) String() string        { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(v string) error    { *f = append(*f, v); return nil }

// cmdReplay implements the replay subcommand.
//
// Single-evidence (backward compatible):
//
//	proofctl replay --claim <id> --generator "cmd {cert}" <digest>
//
// Multi-evidence (one --evidence/--generator pair per certificate):
//
//	proofctl replay --claim <id> \
//	  --evidence sha256:<d1> --generator "cmd --sector odd  --out {cert}" \
//	  --evidence sha256:<d2> --generator "cmd --sector even --out {cert}"
//
// Steps per evidence item:
//  1. Run generator (substituting {cert} with a temp path)
//  2. Compute SHA-256 of generated certificate
//  3. Compare against the expected digest
//  4. Run checker (via BRIDGE_CHECKER or --checker)
//
// A single exact-replay attestation is written only when ALL items pass.
func cmdReplay(args []string, useJSON bool) {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)

	var evidenceFlags multiFlag
	var generatorFlags multiFlag
	fs.Var(&evidenceFlags, "evidence", "evidence digest to replay (repeatable; pairs with --generator)")
	fs.Var(&generatorFlags, "generator", `generator command template with {cert} placeholder (repeatable)`)

	checkerFlag := fs.String("checker", "", "checker command (default: value of BRIDGE_CHECKER env var)")
	claimIDFlag := fs.String("claim", "", "claim ID to attest (required)")
	certOutFlag := fs.String("cert-out", "", "where to write generated certificate (single-evidence only; default: temp file)")

	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	if *claimIDFlag == "" {
		die(useJSON, errors.CodeInvalidInput, "replay: --claim is required")
	}

	// Build evidence/generator pairs. Two supported calling conventions:
	//   (a) --evidence d1 --generator g1 --evidence d2 --generator g2  (multi)
	//   (b) --generator g1 <digest-positional-arg>                      (legacy single)
	type pair struct {
		digest    string
		generator string
	}
	var pairs []pair

	switch {
	case len(evidenceFlags) > 0 && len(generatorFlags) > 0:
		if len(evidenceFlags) != len(generatorFlags) {
			die(useJSON, errors.CodeInvalidInput, fmt.Sprintf(
				"replay: %d --evidence flag(s) but %d --generator flag(s) — counts must match",
				len(evidenceFlags), len(generatorFlags)))
		}
		for i := range evidenceFlags {
			pairs = append(pairs, pair{digest: evidenceFlags[i], generator: generatorFlags[i]})
		}
	case len(generatorFlags) == 1 && fs.NArg() >= 1:
		// Legacy: single --generator + positional digest.
		pairs = append(pairs, pair{digest: fs.Arg(0), generator: generatorFlags[0]})
	default:
		die(useJSON, errors.CodeInvalidInput,
			"replay: use --evidence <digest> --generator <cmd> (repeatable) or legacy --generator <cmd> <digest>")
	}

	checkerCmd := *checkerFlag
	if checkerCmd == "" {
		checkerCmd = os.Getenv("BRIDGE_CHECKER")
	}
	if checkerCmd == "" {
		die(useJSON, errors.CodeInvalidInput, "replay: set --checker or BRIDGE_CHECKER")
	}

	root, _, _, _ := loadProjectGraph(useJSON)
	replayDate := time.Now().UTC().Format("2006-01-02")

	type itemResult struct {
		expectedDigest  string
		generatedDigest string
		digestMatch     bool
		checkerExit     int
		checkerPass     bool
	}

	results := make([]itemResult, len(pairs))
	allPass := true

	for i, p := range pairs {
		label := fmt.Sprintf("evidence[%d] %s", i, p.digest)

		// Resolve certificate output path.
		certPath := ""
		tmpCert := false
		if len(pairs) == 1 && *certOutFlag != "" {
			certPath = *certOutFlag
		} else {
			f, err := os.CreateTemp("", "proofctl-replay-*.json")
			if err != nil {
				die(useJSON, errors.CodeInternalError, "replay: cannot create temp file: "+err.Error())
			}
			certPath = f.Name()
			f.Close()
			tmpCert = true
		}
		if tmpCert {
			defer os.Remove(certPath) //nolint:gocritic // intentional: one deferred remove per temp file
		}

		// Step 1: run generator.
		genCmd := strings.ReplaceAll(p.generator, "{cert}", certPath)
		genParts := strings.Fields(genCmd)
		if !useJSON {
			fmt.Printf("\nreplay %s: running generator: %s\n", label, genCmd)
		}
		genOut, genErr := exec.Command(genParts[0], genParts[1:]...).CombinedOutput()
		if genErr != nil {
			if !useJSON {
				fmt.Printf("  FAIL: generator: %v\n%s\n", genErr, genOut)
			}
			results[i] = itemResult{expectedDigest: p.digest, checkerExit: -1}
			allPass = false
			continue
		}

		// Step 2: SHA-256 of generated certificate.
		f, err := os.Open(certPath)
		if err != nil {
			die(useJSON, errors.CodeInternalError, "replay: cannot open generated cert: "+err.Error())
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			die(useJSON, errors.CodeInternalError, "replay: hash error: "+err.Error())
		}
		f.Close()
		gotDigest := fmt.Sprintf("sha256:%x", h.Sum(nil))
		digestMatch := gotDigest == p.digest

		// Step 3: run checker.
		checkerParts := strings.Fields(checkerCmd)
		checkerParts = append(checkerParts, certPath)
		if !useJSON {
			fmt.Printf("  running checker: %s\n", strings.Join(checkerParts, " "))
		}
		checkerRun := exec.Command(checkerParts[0], checkerParts[1:]...)
		checkerRun.Env = os.Environ()
		checkerExit := 0
		if runErr := checkerRun.Run(); runErr != nil {
			if exitErr, ok := runErr.(*exec.ExitError); ok {
				checkerExit = exitErr.ExitCode()
			} else {
				checkerExit = 1
			}
		}
		checkerPass := checkerExit == 0

		results[i] = itemResult{
			expectedDigest:  p.digest,
			generatedDigest: gotDigest,
			digestMatch:     digestMatch,
			checkerExit:     checkerExit,
			checkerPass:     checkerPass,
		}

		if !digestMatch || !checkerPass {
			allPass = false
		}
		if !useJSON {
			if digestMatch && checkerPass {
				fmt.Printf("  PASS\n")
			} else {
				if !digestMatch {
					fmt.Printf("  FAIL: digest mismatch: got %s, want %s\n", gotDigest, p.digest)
				}
				if !checkerPass {
					fmt.Printf("  FAIL: checker exit %d\n", checkerExit)
				}
			}
		}
	}

	// Write attestation only when all evidence items pass.
	attestPath := ""
	if allPass {
		digests := make([]string, len(pairs))
		generators := make([]string, len(pairs))
		for i, p := range pairs {
			digests[i] = p.digest
			generators[i] = p.generator
		}
		att := ir.Attestation{
			ClaimID:        *claimIDFlag,
			Outcome:        string(ir.StatusAccepted),
			Assurance:      ir.AssuranceExactReplay,
			StartFreshness: replayDate,
			EndFreshness:   replayDate,
			Metadata: map[string]string{
				"cold_replay_date": replayDate,
				"evidence_count":   fmt.Sprintf("%d", len(pairs)),
				"evidence_digests": strings.Join(digests, ","),
				"generator_cmds":   strings.Join(generators, "|"),
				"digests_fresh":    "true",
				"checker_exit":     "0",
			},
		}
		attestDir := filepath.Join(root, config.DirName, config.AttestDir)
		if err := os.MkdirAll(attestDir, 0o755); err != nil {
			die(useJSON, errors.CodeInternalError, "replay: cannot create attestation dir: "+err.Error())
		}
		attestPath = filepath.Join(attestDir, *claimIDFlag+"-replay.json")
		data, _ := json.MarshalIndent(att, "", "  ")
		if err := os.WriteFile(attestPath, append(data, '\n'), 0o644); err != nil {
			die(useJSON, errors.CodeInternalError, "replay: write attestation: "+err.Error())
		}
	}

	if useJSON {
		type itemJSON struct {
			ExpectedDigest  string `json:"expected_digest"`
			GeneratedDigest string `json:"generated_digest,omitempty"`
			DigestMatch     bool   `json:"digest_match"`
			CheckerExit     int    `json:"checker_exit"`
			Pass            bool   `json:"pass"`
		}
		items := make([]itemJSON, len(results))
		for i, res := range results {
			items[i] = itemJSON{
				ExpectedDigest:  res.expectedDigest,
				GeneratedDigest: res.generatedDigest,
				DigestMatch:     res.digestMatch,
				CheckerExit:     res.checkerExit,
				Pass:            res.digestMatch && res.checkerPass,
			}
		}
		out := map[string]any{
			"pass":             allPass,
			"claim_id":         *claimIDFlag,
			"cold_replay_date": replayDate,
			"evidence":         items,
			"attestation":      attestPath,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		fmt.Printf("\n--- Replay Report ---\n")
		fmt.Printf("claim:    %s\n", *claimIDFlag)
		fmt.Printf("date:     %s\n", replayDate)
		fmt.Printf("evidence: %d item(s)\n", len(pairs))
		if allPass {
			fmt.Printf("\nREPLAY PASS — attestation written to %s\n", attestPath)
		} else {
			fmt.Println("\nREPLAY FAIL")
			os.Exit(1)
		}
	}
}
