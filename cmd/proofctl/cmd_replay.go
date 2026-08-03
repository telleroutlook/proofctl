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

// cmdReplay implements the replay subcommand.
//
// Usage:
//
//	proofctl replay --generator "cmd {cert}" --cert-out /tmp/cert.json <evidence-digest>
//
// Steps:
//  1. Run generator (substituting {cert} with a temp path)
//  2. Compute SHA-256 of generated certificate
//  3. Compare against the expected evidence digest
//  4. Run checker (via BRIDGE_CHECKER or --checker flag) against the generated cert
//  5. Write a replay attestation (assurance: exact-replay) to .proofctl/attestations/
//  6. Print replay report
func cmdReplay(args []string, useJSON bool) {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	generatorFlag := fs.String("generator", "", `generator command template; use {cert} as placeholder for output path, e.g. "python -m src.generate_certificate --out {cert}"`)
	certOutFlag := fs.String("cert-out", "", "where to write the generated certificate (default: temp file, deleted after replay)")
	checkerFlag := fs.String("checker", "", "checker command (default: value of BRIDGE_CHECKER env var)")
	claimIDFlag := fs.String("claim", "", "claim ID to attest (required)")
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	if *generatorFlag == "" {
		die(useJSON, errors.CodeInvalidInput, "replay: --generator is required")
	}
	if *claimIDFlag == "" {
		die(useJSON, errors.CodeInvalidInput, "replay: --claim is required")
	}
	if fs.NArg() < 1 {
		die(useJSON, errors.CodeInvalidInput, "replay: expected <evidence-digest> argument")
	}
	expectedDigest := fs.Arg(0)

	checkerCmd := *checkerFlag
	if checkerCmd == "" {
		checkerCmd = os.Getenv("BRIDGE_CHECKER")
	}
	if checkerCmd == "" {
		die(useJSON, errors.CodeInvalidInput, "replay: set --checker or BRIDGE_CHECKER")
	}

	root, _, _, _ := loadProjectGraph(useJSON)

	// Determine certificate output path.
	certPath := *certOutFlag
	tmpCert := false
	if certPath == "" {
		f, err := os.CreateTemp("", "proofctl-replay-*.json")
		if err != nil {
			die(useJSON, errors.CodeInternalError, "replay: cannot create temp file: "+err.Error())
		}
		certPath = f.Name()
		f.Close()
		tmpCert = true
	}
	if tmpCert {
		defer os.Remove(certPath)
	}

	replayDate := time.Now().UTC().Format("2006-01-02")

	// Step 1: run generator.
	genCmd := strings.ReplaceAll(*generatorFlag, "{cert}", certPath)
	genParts := strings.Fields(genCmd)
	if !useJSON {
		fmt.Printf("replay: running generator: %s\n", genCmd)
	}
	genOut, err := exec.Command(genParts[0], genParts[1:]...).CombinedOutput()
	if err != nil {
		msg := fmt.Sprintf("generator failed: %v\n%s", err, genOut)
		die(useJSON, errors.CodeInternalError, msg)
	}

	// Step 2: compute SHA-256 of generated certificate.
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

	digestMatch := gotDigest == expectedDigest

	// Step 3: run checker via bridge.
	checkerParts := strings.Fields(checkerCmd)
	checkerParts = append(checkerParts, certPath)
	if !useJSON {
		fmt.Printf("replay: running checker: %s\n", strings.Join(checkerParts, " "))
	}
	checkerResult := struct {
		exit int
		out  []byte
	}{}
	checkerRun := exec.Command(checkerParts[0], checkerParts[1:]...)
	checkerRun.Env = os.Environ()
	checkerResult.out, _ = checkerRun.CombinedOutput()
	checkerResult.exit = 0
	if err := checkerRun.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			checkerResult.exit = exitErr.ExitCode()
		} else {
			checkerResult.exit = 1
		}
	}

	checkerPass := checkerResult.exit == 0
	replayPass := digestMatch && checkerPass

	// Step 4: write attestation if replay passed.
	attestPath := ""
	if replayPass {
		att := ir.Attestation{
			ClaimID:        *claimIDFlag,
			Outcome:        string(ir.StatusAccepted),
			Assurance:      ir.AssuranceExactReplay,
			StartFreshness: replayDate,
			EndFreshness:   replayDate,
			Metadata: map[string]string{
				"cold_replay_date":   replayDate,
				"generator_cmd":      *generatorFlag,
				"expected_digest":    expectedDigest,
				"generated_digest":   gotDigest,
				"checker_exit":       fmt.Sprintf("%d", checkerResult.exit),
				"digests_fresh":      "true",
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
		out := map[string]any{
			"pass":             replayPass,
			"claim_id":         *claimIDFlag,
			"expected_digest":  expectedDigest,
			"generated_digest": gotDigest,
			"digest_match":     digestMatch,
			"checker_exit":     checkerResult.exit,
			"checker_pass":     checkerPass,
			"cold_replay_date": replayDate,
			"attestation":      attestPath,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		fmt.Printf("\n--- Replay Report ---\n")
		fmt.Printf("claim:            %s\n", *claimIDFlag)
		fmt.Printf("expected digest:  %s\n", expectedDigest)
		fmt.Printf("generated digest: %s\n", gotDigest)
		fmt.Printf("digest match:     %v\n", digestMatch)
		fmt.Printf("checker exit:     %d\n", checkerResult.exit)
		fmt.Printf("date:             %s\n", replayDate)
		if replayPass {
			fmt.Printf("\nREPLAY PASS — attestation written to %s\n", attestPath)
		} else {
			fmt.Println("\nREPLAY FAIL")
			if !digestMatch {
				fmt.Printf("  digest mismatch: got %s, want %s\n", gotDigest, expectedDigest)
			}
			if !checkerPass {
				fmt.Printf("  checker exit %d\n", checkerResult.exit)
			}
			os.Exit(1)
		}
	}
}
