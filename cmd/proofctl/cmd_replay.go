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

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// multiFlag is a repeatable string flag that collects all occurrences.
type multiFlag []string

func (f *multiFlag) String() string     { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(v string) error { *f = append(*f, v); return nil }

// replayPair is one evidence/generator pair.
type replayPair struct {
	digest    string
	generator string
}

// replayItemResult captures the per-evidence outcome.
type replayItemResult struct {
	expectedDigest  string
	generatedDigest string
	digestMatch     bool
	checkerExit     int
	checkerPass     bool
	failReason      string // detailed, set on failure
	checkerOutput   string // combined checker output on failure
}

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
//  3. Compare against the expected digest (skipped with --semantic)
//  4. Run checker (via BRIDGE_CHECKER or --checker)
//
// A single attestation is written only when ALL items pass.
// When some items fail, a partial-result debug file is written for incremental debugging.
func cmdReplay(args []string, useJSON bool) {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)

	var evidenceFlags multiFlag
	var generatorFlags multiFlag
	fs.Var(&evidenceFlags, "evidence", "evidence digest to replay (repeatable; pairs with --generator)")
	fs.Var(&generatorFlags, "generator", `generator command template with {cert} placeholder (repeatable)`)

	checkerFlag := fs.String("checker", "", "checker command (default: value of BRIDGE_CHECKER env var)")
	claimIDFlag := fs.String("claim", "", "claim ID to attest (required unless --batch)")
	certOutFlag := fs.String("cert-out", "", "where to write generated certificate (single-evidence only; default: temp file)")
	semanticFlag := fs.Bool("semantic", false, "semantic-replay: checker pass is sufficient; skip exact digest comparison")
	dryRunFlag := fs.Bool("dry-run", false, "validate inputs and CAS state without running the generator or writing attestations")
	batchFlag := fs.String("batch", "", "path to batch manifest JSON for replaying multiple claims")
	skipAcceptedFlag := fs.Bool("skip-if-accepted", false, "skip claims that already have an accepted attestation with non-empty freshness")
	reuseGeneratedFlag := fs.String("reuse-generated", "", "directory containing already-generated cert files; skip generator step and reuse <evidence-hex>.json")

	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, err.Error())
	}

	// Batch replay path.
	if *batchFlag != "" {
		cmdReplayBatch(*batchFlag, *skipAcceptedFlag, useJSON)
		return
	}

	if *claimIDFlag == "" {
		die(useJSON, errors.CodeInvalidInput, "replay: --claim is required (or use --batch <manifest.json>)")
	}

	var pairs []replayPair

	switch {
	case len(evidenceFlags) > 0 && len(generatorFlags) > 0:
		if len(evidenceFlags) != len(generatorFlags) {
			die(useJSON, errors.CodeInvalidInput, fmt.Sprintf(
				"replay: %d --evidence flag(s) but %d --generator flag(s) — counts must match",
				len(evidenceFlags), len(generatorFlags)))
		}
		for i := range evidenceFlags {
			pairs = append(pairs, replayPair{digest: evidenceFlags[i], generator: generatorFlags[i]})
		}
	case len(generatorFlags) == 1 && fs.NArg() >= 1:
		// Legacy: single --generator + positional digest.
		pairs = append(pairs, replayPair{digest: fs.Arg(0), generator: generatorFlags[0]})
	default:
		die(useJSON, errors.CodeInvalidInput,
			"replay: use --evidence <digest> --generator <cmd> (repeatable) or legacy --generator <cmd> <digest>")
	}

	// Validate every generator template contains {cert}.
	for i, p := range pairs {
		if !strings.Contains(p.generator, "{cert}") {
			die(useJSON, errors.CodeInvalidInput,
				fmt.Sprintf("replay: evidence[%d] generator %q is missing {cert} placeholder", i, p.generator))
		}
	}

	checkerCmd := *checkerFlag
	if checkerCmd == "" {
		checkerCmd = os.Getenv("BRIDGE_CHECKER")
	}
	if checkerCmd == "" {
		die(useJSON, errors.CodeInvalidInput, "replay: set --checker or BRIDGE_CHECKER")
	}

	root, _, _, attestations := loadProjectGraph(useJSON)
	casRoot := filepath.Join(root, config.DirName, config.CASDir)
	replayDate := time.Now().UTC().Format("2006-01-02")

	// --skip-if-accepted: exit early if already accepted with freshness.
	if *skipAcceptedFlag {
		if att, ok := attestations[*claimIDFlag]; ok &&
			att.Outcome == string(ir.StatusAccepted) &&
			att.StartFreshness != "" && att.EndFreshness != "" {
			if !useJSON {
				fmt.Printf("SKIP  %s — already accepted (assurance=%s, freshness=%s)\n",
					*claimIDFlag, att.Assurance, att.StartFreshness)
			} else {
				enc := json.NewEncoder(os.Stdout)
				_ = enc.Encode(map[string]any{"skipped": true, "claim_id": *claimIDFlag,
					"reason": "already accepted with freshness"})
			}
			return
		}
	}

	if *dryRunFlag {
		runReplayDryRun(pairs, casRoot, root, checkerCmd, *claimIDFlag, useJSON)
		return
	}

	results := make([]replayItemResult, len(pairs))
	allPass := true
	replayStart := time.Now()

	for i, p := range pairs {
		// --reuse-generated: use pre-generated cert from directory instead of running generator.
		if *reuseGeneratedFlag != "" {
			hexPart := strings.TrimPrefix(p.digest, "sha256:")
			if len(hexPart) > 16 {
				hexPart = hexPart[:16]
			}
			candidatePath := filepath.Join(*reuseGeneratedFlag, hexPart+".json")
			if _, statErr := os.Stat(candidatePath); statErr == nil {
				// Patch the generator to copy the pre-generated file.
				p.generator = "cp " + candidatePath + " {cert}"
			}
		}
		label := fmt.Sprintf("evidence[%d] %s", i, p.digest)

		// Auto-import from path_hint if the digest is not yet in CAS.
		if !casHasDigest(casRoot, p.digest) {
			imported, importErr := autoImportFromPathHint(root, casRoot, p.digest)
			if importErr != nil && !useJSON {
				fmt.Printf("  warning: auto-import failed for %s: %v\n", p.digest, importErr)
			} else if imported && !useJSON {
				fmt.Printf("  auto-imported %s from path_hint\n", p.digest)
			}
		}

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
			_ = f.Close()
			tmpCert = true
		}
		if tmpCert {
			defer os.Remove(certPath) //nolint:gocritic,errcheck // intentional: cleanup on exit; error irrelevant
		}

		// Step 1: run generator.
		genCmd := strings.ReplaceAll(p.generator, "{cert}", certPath)
		genParts := strings.Fields(genCmd)
		if !useJSON {
			fmt.Printf("\nreplay %s: running generator: %s\n", label, genCmd)
		}
		genOut, genErr := exec.Command(genParts[0], genParts[1:]...).CombinedOutput()
		if genErr != nil {
			reason := fmt.Sprintf("generator failed: %v", genErr)
			if len(genOut) > 0 {
				reason += "\n  generator output:\n" + indentLines(string(genOut), "    ")
			}
			if !useJSON {
				fmt.Printf("  FAIL: %s\n", reason)
			}
			results[i] = replayItemResult{expectedDigest: p.digest, checkerExit: -1, failReason: reason}
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
			_ = f.Close()
			die(useJSON, errors.CodeInternalError, "replay: hash error: "+err.Error())
		}
		_ = f.Close()
		gotDigest := fmt.Sprintf("sha256:%x", h.Sum(nil))
		digestMatch := gotDigest == p.digest || *semanticFlag

		// Step 3: run checker.
		checkerParts := append(strings.Fields(checkerCmd), certPath)
		if !useJSON {
			fmt.Printf("  running checker: %s\n", strings.Join(checkerParts, " "))
		}
		checkerRun := exec.Command(checkerParts[0], checkerParts[1:]...)
		checkerRun.Env = os.Environ()
		checkerOut, _ := checkerRun.CombinedOutput()
		checkerExit := 0
		if checkerRun.ProcessState != nil {
			checkerExit = checkerRun.ProcessState.ExitCode()
		}
		checkerPass := checkerExit == 0

		// Build failure reason with all available detail.
		failReason := ""
		if !digestMatch {
			failReason = buildDigestMismatchReason(gotDigest, p.digest, certPath, casRoot)
		}
		if !checkerPass {
			checkerReason := fmt.Sprintf("checker exited %d", checkerExit)
			if len(checkerOut) > 0 {
				checkerReason += "\n  checker output:\n" + indentLines(string(checkerOut), "    ")
			}
			if failReason != "" {
				failReason += "\n" + checkerReason
			} else {
				failReason = checkerReason
			}
		}

		results[i] = replayItemResult{
			expectedDigest:  p.digest,
			generatedDigest: gotDigest,
			digestMatch:     digestMatch,
			checkerExit:     checkerExit,
			checkerPass:     checkerPass,
			failReason:      failReason,
			checkerOutput:   string(checkerOut),
		}

		if !digestMatch || !checkerPass {
			allPass = false
		}
		if !useJSON {
			if digestMatch && checkerPass {
				fmt.Printf("  PASS\n")
			} else {
				if !digestMatch {
					fmt.Printf("  FAIL: %s\n", buildDigestMismatchReason(gotDigest, p.digest, certPath, casRoot))
				}
				if !checkerPass {
					fmt.Printf("  FAIL: checker exit %d", checkerExit)
					if len(checkerOut) > 0 {
						fmt.Printf("\n  checker output:\n%s", indentLines(string(checkerOut), "    "))
					}
					fmt.Println()
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
		assurance := ir.AssuranceExactReplay
		if *semanticFlag {
			assurance = ir.AssuranceReproducibleComputation
		}
		wallMillis := time.Since(replayStart).Milliseconds()
		att := ir.Attestation{
			ClaimID:        *claimIDFlag,
			Outcome:        string(ir.StatusAccepted),
			Assurance:      assurance,
			ReplayMode:     "from_scratch",
			StartFreshness: replayDate,
			EndFreshness:   replayDate,
			Resources: ir.ResourceStats{
				WallMillis: wallMillis,
			},
			Metadata: map[string]string{
				"cold_replay_date": replayDate,
				"evidence_count":   fmt.Sprintf("%d", len(pairs)),
				"evidence_digests": strings.Join(digests, ","),
				"generator_cmds":   strings.Join(generators, "|"),
				"digests_fresh":    "true",
				"checker_exit":     "0",
				"semantic_replay":  fmt.Sprintf("%v", *semanticFlag),
			},
		}
		if sd, sdErr := ir.DigestOf(&att); sdErr == nil {
			att.SelfDigest = sd
		}
		attestDir := filepath.Join(root, config.DirName, config.AttestDir)
		if err := os.MkdirAll(attestDir, 0o755); err != nil {
			die(useJSON, errors.CodeInternalError, "replay: cannot create attestation dir: "+err.Error())
		}
		attestPath = filepath.Join(attestDir, *claimIDFlag+".json")
		data, _ := json.MarshalIndent(att, "", "  ")
		if err := os.WriteFile(attestPath, append(data, '\n'), 0o644); err != nil {
			die(useJSON, errors.CodeInternalError, "replay: write attestation: "+err.Error())
		}
	} else {
		// Write partial debug record so the caller can see which items passed.
		writePartialReplayRecord(*claimIDFlag, replayDate, results, root, useJSON)
	}

	if useJSON {
		type itemJSON struct {
			ExpectedDigest  string `json:"expected_digest"`
			GeneratedDigest string `json:"generated_digest,omitempty"`
			DigestMatch     bool   `json:"digest_match"`
			CheckerExit     int    `json:"checker_exit"`
			Pass            bool   `json:"pass"`
			FailReason      string `json:"fail_reason,omitempty"`
			CheckerOutput   string `json:"checker_output,omitempty"`
		}
		items := make([]itemJSON, len(results))
		for i, res := range results {
			items[i] = itemJSON{
				ExpectedDigest:  res.expectedDigest,
				GeneratedDigest: res.generatedDigest,
				DigestMatch:     res.digestMatch,
				CheckerExit:     res.checkerExit,
				Pass:            res.digestMatch && res.checkerPass,
				FailReason:      res.failReason,
				CheckerOutput:   res.checkerOutput,
			}
		}
		out := map[string]any{
			"pass":             allPass,
			"claim_id":         *claimIDFlag,
			"cold_replay_date": replayDate,
			"semantic":         *semanticFlag,
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
		fmt.Printf("mode:     %s\n", replayModeLabel(*semanticFlag))
		fmt.Printf("evidence: %d item(s)\n", len(pairs))
		if allPass {
			fmt.Printf("\nREPLAY PASS — attestation written to %s\n", attestPath)
		} else {
			fmt.Println("\nREPLAY FAIL")
			for i, res := range results {
				if !res.digestMatch || !res.checkerPass {
					fmt.Printf("  evidence[%d] %s\n", i, res.expectedDigest)
					if res.failReason != "" {
						fmt.Printf("    reason: %s\n",
							strings.ReplaceAll(res.failReason, "\n", "\n    "))
					}
				}
			}
			os.Exit(1)
		}
	}
}

// runReplayDryRun validates CAS state and generator syntax without executing anything.
func runReplayDryRun(pairs []replayPair, casRoot, root, checkerCmd, claimID string, useJSON bool) {
	type dryItem struct {
		Digest             string `json:"digest"`
		InCAS              bool   `json:"in_cas"`
		PathHint           string `json:"path_hint,omitempty"`
		HasCertPlaceholder bool   `json:"has_cert_placeholder"`
	}

	pg := loadCompiledGraph(root)
	var items []dryItem
	allOK := true

	for _, p := range pairs {
		inCAS := casHasDigest(casRoot, p.digest)
		hasCert := strings.Contains(p.generator, "{cert}")
		hint := ""
		if pg != nil {
			for _, ev := range pg.Evidence {
				if ev.Digest == p.digest && ev.PathHint != "" {
					hint = ev.PathHint
					break
				}
			}
		}
		items = append(items, dryItem{
			Digest:             p.digest,
			InCAS:              inCAS,
			PathHint:           hint,
			HasCertPlaceholder: hasCert,
		})
		if !inCAS || !hasCert {
			allOK = false
		}
	}

	checkerParts := strings.Fields(checkerCmd)
	checkerResolvable := false
	if len(checkerParts) > 0 {
		if _, err := exec.LookPath(checkerParts[0]); err == nil {
			checkerResolvable = true
		} else if _, statErr := os.Stat(checkerParts[0]); statErr == nil {
			checkerResolvable = true
		}
	}
	if !checkerResolvable {
		allOK = false
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"dry_run":            true,
			"claim_id":           claimID,
			"ok":                 allOK,
			"checker_resolvable": checkerResolvable,
			"checker_cmd":        checkerCmd,
			"evidence":           items,
		})
		return
	}

	fmt.Printf("--- Dry Run: %s ---\n", claimID)
	fmt.Printf("checker: %s", checkerCmd)
	if checkerResolvable {
		fmt.Println(" [ok]")
	} else {
		fmt.Printf(" [NOT FOUND in PATH or filesystem]\n")
	}
	for i, it := range items {
		casStatus := "in CAS [ok]"
		if !it.InCAS {
			if it.PathHint != "" {
				casStatus = fmt.Sprintf("NOT in CAS — can auto-import from %s", it.PathHint)
			} else {
				casStatus = "NOT in CAS, no path_hint known — run 'proofctl cas import <file>'"
			}
		}
		certStatus := "has {cert} placeholder [ok]"
		if !it.HasCertPlaceholder {
			certStatus = "MISSING {cert} placeholder — generator cannot write output"
		}
		fmt.Printf("  evidence[%d] %s\n    CAS:       %s\n    generator: %s\n", i, it.Digest, casStatus, certStatus)
	}
	if allOK {
		fmt.Println("\nDRY RUN OK — ready to replay")
	} else {
		fmt.Println("\nDRY RUN FAIL — fix the issues above before replaying")
		os.Exit(1)
	}
}

// casHasDigest reports whether the given sha256 digest is present in the CAS.
func casHasDigest(casRoot, digest string) bool {
	hexPart := strings.TrimPrefix(digest, "sha256:")
	if len(hexPart) < 4 {
		return false
	}
	blobPath := filepath.Join(casRoot, "sha256", hexPart[:2], hexPart[2:])
	_, err := os.Stat(blobPath)
	return err == nil
}

// autoImportFromPathHint looks up the digest in the compiled graph's evidence list,
// finds a path_hint, and imports the file into the CAS. Returns true if imported.
func autoImportFromPathHint(root, casRoot, digest string) (bool, error) {
	pg := loadCompiledGraph(root)
	if pg == nil {
		return false, nil
	}
	for _, ev := range pg.Evidence {
		if ev.Digest != digest || ev.PathHint == "" {
			continue
		}
		f, err := os.Open(ev.PathHint)
		if err != nil {
			return false, fmt.Errorf("open path_hint %s: %w", ev.PathHint, err)
		}
		defer func() { _ = f.Close() }()
		store, err := cas.New(casRoot)
		if err != nil {
			return false, fmt.Errorf("open CAS: %w", err)
		}
		gotDigest, _, _, err := store.Store(f)
		if err != nil {
			return false, fmt.Errorf("CAS store: %w", err)
		}
		if gotDigest != digest {
			return false, fmt.Errorf("digest mismatch after import: file %s has %s, expected %s",
				ev.PathHint, gotDigest, digest)
		}
		return true, nil
	}
	return false, nil
}

// buildDigestMismatchReason constructs a detailed mismatch message.
// When both the old cert (from CAS) and new cert contain sha256_inputs, it diffs them.
func buildDigestMismatchReason(gotDigest, wantDigest, newCertPath, casRoot string) string {
	msg := fmt.Sprintf("digest mismatch: got %s, want %s", gotDigest, wantDigest)

	newInputs := extractSHA256Inputs(newCertPath)
	oldInputs := extractSHA256InputsFromCAS(casRoot, wantDigest)

	if len(newInputs) == 0 && len(oldInputs) == 0 {
		return msg
	}

	if len(oldInputs) == 0 {
		msg += "\n  new cert has sha256_inputs but old cert not in CAS — cannot diff"
		return msg
	}

	allKeys := make(map[string]bool)
	for k := range oldInputs {
		allKeys[k] = true
	}
	for k := range newInputs {
		allKeys[k] = true
	}
	changed := false
	diff := ""
	for k := range allKeys {
		oldV, inOld := oldInputs[k]
		newV, inNew := newInputs[k]
		switch {
		case !inOld:
			diff += fmt.Sprintf("\n    + %s: %s (added)", k, newV)
			changed = true
		case !inNew:
			diff += fmt.Sprintf("\n    - %s: %s (removed)", k, oldV)
			changed = true
		case oldV != newV:
			diff += fmt.Sprintf("\n    ~ %s\n        old: %s\n        new: %s", k, oldV, newV)
			changed = true
		}
	}
	if changed {
		msg += "\n  sha256_inputs changed (source files modified since last cert):" + diff
		msg += "\n  hint: use --semantic to accept checker-verified results regardless of digest"
	} else {
		msg += "\n  sha256_inputs are identical — mismatch is in another cert field"
	}
	return msg
}

// extractSHA256Inputs reads cert JSON and returns the sha256_inputs map, or nil.
func extractSHA256Inputs(certPath string) map[string]string {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil
	}
	return extractSHA256InputsFromJSON(data)
}

// extractSHA256InputsFromCAS opens a blob from CAS by digest and extracts sha256_inputs.
func extractSHA256InputsFromCAS(casRoot, digest string) map[string]string {
	hexPart := strings.TrimPrefix(digest, "sha256:")
	if len(hexPart) < 4 {
		return nil
	}
	blobPath := filepath.Join(casRoot, "sha256", hexPart[:2], hexPart[2:])
	data, err := os.ReadFile(blobPath)
	if err != nil {
		return nil
	}
	return extractSHA256InputsFromJSON(data)
}

func extractSHA256InputsFromJSON(data []byte) map[string]string {
	var cert map[string]any
	if err := json.Unmarshal(data, &cert); err != nil {
		return nil
	}
	raw, ok := cert["sha256_inputs"]
	if !ok {
		return nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result
}

// writePartialReplayRecord writes a debug file when some evidence items pass and some fail.
func writePartialReplayRecord(claimID, date string, results []replayItemResult, root string, useJSON bool) {
	hasAttempt := false
	for _, r := range results {
		if r.generatedDigest != "" || r.failReason != "" {
			hasAttempt = true
			break
		}
	}
	if !hasAttempt {
		return
	}

	type itemRecord struct {
		Digest      string `json:"digest"`
		Pass        bool   `json:"pass"`
		DigestMatch bool   `json:"digest_match"`
		CheckerExit int    `json:"checker_exit"`
		FailReason  string `json:"fail_reason,omitempty"`
	}
	type partialRecord struct {
		ClaimID  string       `json:"claim_id"`
		Outcome  string       `json:"outcome"`
		Date     string       `json:"date"`
		Note     string       `json:"note"`
		Evidence []itemRecord `json:"evidence"`
	}

	rec := partialRecord{
		ClaimID: claimID,
		Outcome: "partial",
		Date:    date,
		Note:    "debug record only — not a valid attestation; claim remains OPEN",
	}
	for _, r := range results {
		rec.Evidence = append(rec.Evidence, itemRecord{
			Digest:      r.expectedDigest,
			Pass:        r.digestMatch && r.checkerPass,
			DigestMatch: r.digestMatch,
			CheckerExit: r.checkerExit,
			FailReason:  r.failReason,
		})
	}

	attestDir := filepath.Join(root, config.DirName, config.AttestDir)
	_ = os.MkdirAll(attestDir, 0o755)
	partialPath := filepath.Join(attestDir, claimID+"-replay-partial.json")
	data, _ := json.MarshalIndent(rec, "", "  ")
	if writeErr := os.WriteFile(partialPath, append(data, '\n'), 0o644); writeErr == nil && !useJSON {
		fmt.Printf("  partial debug record written to %s\n", partialPath)
	}
}

func replayModeLabel(semantic bool) string {
	if semantic {
		return "semantic (checker-pass only, digest not compared)"
	}
	return "exact (digest + checker)"
}

// indentLines prepends prefix to every line of s.
func indentLines(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

// batchReplayEntry is one record in a --batch manifest file.
// Evidence/generator pairs are shared across all claims in the entry —
// the generator runs once and each claim gets an attestation.
type batchReplayEntry struct {
	Claims    []string `json:"claims"`
	Evidence  []string `json:"evidence"`
	Generator []string `json:"generator"`
	Semantic  bool     `json:"semantic"`
	Checker   string   `json:"checker,omitempty"`
}

// cmdReplayBatch reads a JSON manifest and executes replay for each entry.
// Within an entry, the generator runs once; all listed claims share the result.
func cmdReplayBatch(manifestPath string, skipAccepted bool, useJSON bool) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, "replay --batch: read manifest: "+err.Error())
	}
	var entries []batchReplayEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		die(useJSON, errors.CodeInvalidInput, "replay --batch: parse manifest: "+err.Error())
	}
	if len(entries) == 0 {
		die(useJSON, errors.CodeInvalidInput, "replay --batch: manifest contains no entries")
	}

	root, _, _, attestations := loadProjectGraph(useJSON)
	casRoot := filepath.Join(root, config.DirName, config.CASDir)
	attestDir := filepath.Join(root, config.DirName, config.AttestDir)
	replayDate := time.Now().UTC().Format("2006-01-02")

	if err := os.MkdirAll(attestDir, 0o755); err != nil {
		die(useJSON, errors.CodeInternalError, "replay --batch: mkdir attestations: "+err.Error())
	}

	type batchResult struct {
		ClaimID    string `json:"claim_id"`
		Pass       bool   `json:"pass"`
		Skipped    bool   `json:"skipped,omitempty"`
		SkipReason string `json:"skip_reason,omitempty"`
		AttestPath string `json:"attestation,omitempty"`
		FailReason string `json:"fail_reason,omitempty"`
	}
	var allResults []batchResult
	totalPass, totalFail, totalSkip := 0, 0, 0

	for entryIdx, entry := range entries {
		if len(entry.Claims) == 0 {
			continue
		}
		if len(entry.Evidence) != len(entry.Generator) {
			die(useJSON, errors.CodeInvalidInput, fmt.Sprintf(
				"replay --batch: entry %d: %d evidence items but %d generators — counts must match",
				entryIdx, len(entry.Evidence), len(entry.Generator)))
		}

		checkerCmd := entry.Checker
		if checkerCmd == "" {
			checkerCmd = os.Getenv("BRIDGE_CHECKER")
		}
		if checkerCmd == "" {
			die(useJSON, errors.CodeInvalidInput, fmt.Sprintf(
				"replay --batch: entry %d: no checker — set entry.checker or BRIDGE_CHECKER", entryIdx))
		}

		pairs := make([]replayPair, len(entry.Evidence))
		for i := range entry.Evidence {
			pairs[i] = replayPair{digest: entry.Evidence[i], generator: entry.Generator[i]}
		}

		// Determine which claims in this entry still need work.
		// When --skip-if-accepted is set, record already-accepted claims and
		// collect the remainder. If all claims are already accepted, skip the
		// entire entry (no need to run the generator).
		var pendingClaims []string
		for _, claimID := range entry.Claims {
			if skipAccepted {
				if att, ok := attestations[claimID]; ok &&
					att.Outcome == string(ir.StatusAccepted) &&
					att.StartFreshness != "" {
					allResults = append(allResults, batchResult{
						ClaimID: claimID, Pass: true, Skipped: true,
						SkipReason: "already accepted with freshness",
					})
					totalSkip++
					continue
				}
			}
			pendingClaims = append(pendingClaims, claimID)
		}
		if len(pendingClaims) == 0 {
			continue
		}

		// Run evidence generation once for this entry (shared across all claims).
		if !useJSON {
			fmt.Printf("\n[entry %d] generating %d evidence item(s) for %d claim(s)\n",
				entryIdx, len(pairs), len(entry.Claims))
		}

		certPaths := make([]string, len(pairs))
		entryPass := true
		var firstFailReason string

		for i, p := range pairs {
			// Auto-import from path_hint if needed.
			if !casHasDigest(casRoot, p.digest) {
				imported, importErr := autoImportFromPathHint(root, casRoot, p.digest)
				if importErr != nil && !useJSON {
					fmt.Printf("  warning: auto-import failed for %s: %v\n", p.digest, importErr)
				} else if imported && !useJSON {
					fmt.Printf("  auto-imported %s\n", p.digest)
				}
			}

			f, tmpErr := os.CreateTemp("", "proofctl-batch-replay-*.json")
			if tmpErr != nil {
				die(useJSON, errors.CodeInternalError, "replay --batch: create temp: "+tmpErr.Error())
			}
			certPath := f.Name()
			_ = f.Close()
			defer os.Remove(certPath) //nolint:gocritic,errcheck

			certPaths[i] = certPath
			genCmd := strings.ReplaceAll(p.generator, "{cert}", certPath)
			genParts := strings.Fields(genCmd)
			if !useJSON {
				fmt.Printf("  evidence[%d]: running generator: %s\n", i, genCmd)
			}
			genOut, genErr := exec.Command(genParts[0], genParts[1:]...).CombinedOutput()
			if genErr != nil {
				reason := fmt.Sprintf("evidence[%d] generator failed: %v", i, genErr)
				if len(genOut) > 0 {
					reason += "\n" + indentLines(string(genOut), "    ")
				}
				entryPass = false
				firstFailReason = reason
				break
			}
		}

		if !entryPass {
			for _, claimID := range pendingClaims {
				allResults = append(allResults, batchResult{
					ClaimID: claimID, Pass: false, FailReason: firstFailReason,
				})
				totalFail++
			}
			continue
		}

		// Run checker once per evidence item — shared for all claims.
		checkerResults := make([]replayItemResult, len(pairs))
		allCheckerPass := true
		for i, p := range pairs {
			certPath := certPaths[i]
			checkerParts := append(strings.Fields(checkerCmd), certPath)
			if !useJSON {
				fmt.Printf("  evidence[%d]: running checker\n", i)
			}
			checkerRun := exec.Command(checkerParts[0], checkerParts[1:]...)
			checkerRun.Env = os.Environ()
			checkerOut, _ := checkerRun.CombinedOutput()
			checkerExit := 0
			if checkerRun.ProcessState != nil {
				checkerExit = checkerRun.ProcessState.ExitCode()
			}
			checkerPass := checkerExit == 0

			// Digest comparison (unless semantic).
			var h [32]byte
			if certData, readErr := os.ReadFile(certPath); readErr == nil {
				h = sha256.Sum256(certData)
			}
			gotDigest := fmt.Sprintf("sha256:%x", h)
			digestMatch := gotDigest == p.digest || entry.Semantic

			failReason := ""
			if !digestMatch {
				failReason = buildDigestMismatchReason(gotDigest, p.digest, certPath, casRoot)
			}
			if !checkerPass {
				cr := fmt.Sprintf("checker exited %d", checkerExit)
				if len(checkerOut) > 0 {
					cr += "\n" + indentLines(string(checkerOut), "    ")
				}
				if failReason != "" {
					failReason += "\n" + cr
				} else {
					failReason = cr
				}
			}
			checkerResults[i] = replayItemResult{
				expectedDigest:  p.digest,
				generatedDigest: gotDigest,
				digestMatch:     digestMatch,
				checkerExit:     checkerExit,
				checkerPass:     checkerPass,
				failReason:      failReason,
				checkerOutput:   string(checkerOut),
			}
			if !digestMatch || !checkerPass {
				allCheckerPass = false
			}
		}

		if !allCheckerPass {
			var reasons []string
			for i, r := range checkerResults {
				if r.failReason != "" {
					reasons = append(reasons, fmt.Sprintf("evidence[%d]: %s", i, r.failReason))
				}
			}
			failMsg := strings.Join(reasons, "; ")
			for _, claimID := range pendingClaims {
				allResults = append(allResults, batchResult{
					ClaimID: claimID, Pass: false, FailReason: failMsg,
				})
				totalFail++
			}
			continue
		}

		// All checks passed — write one attestation per pending claim.
		assurance := ir.AssuranceExactReplay
		if entry.Semantic {
			assurance = ir.AssuranceReproducibleComputation
		}
		digests := entry.Evidence
		generators := entry.Generator

		for _, claimID := range pendingClaims {

			att := ir.Attestation{
				ClaimID:        claimID,
				Outcome:        string(ir.StatusAccepted),
				Assurance:      assurance,
				ReplayMode:     "from_scratch",
				StartFreshness: replayDate,
				EndFreshness:   replayDate,
				Metadata: map[string]string{
					"cold_replay_date": replayDate,
					"evidence_count":   fmt.Sprintf("%d", len(pairs)),
					"evidence_digests": strings.Join(digests, ","),
					"generator_cmds":   strings.Join(generators, "|"),
					"digests_fresh":    "true",
					"checker_exit":     "0",
					"semantic_replay":  fmt.Sprintf("%v", entry.Semantic),
					"batch_entry":      fmt.Sprintf("%d", entryIdx),
				},
			}
			if sd, sdErr := ir.DigestOf(&att); sdErr == nil {
				att.SelfDigest = sd
			}
			attPath := filepath.Join(attestDir, claimID+".json")
			attData, _ := json.MarshalIndent(att, "", "  ")
			if writeErr := os.WriteFile(attPath, append(attData, '\n'), 0o644); writeErr != nil {
				allResults = append(allResults, batchResult{
					ClaimID: claimID, Pass: false,
					FailReason: "write attestation: " + writeErr.Error(),
				})
				totalFail++
				continue
			}
			allResults = append(allResults, batchResult{
				ClaimID: claimID, Pass: true, AttestPath: attPath,
			})
			totalPass++
			if !useJSON {
				fmt.Printf("  PASS  %s → %s\n", claimID, attPath)
			}
		}
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"pass":    totalFail == 0,
			"results": allResults,
			"summary": map[string]int{"passed": totalPass, "failed": totalFail, "skipped": totalSkip},
		})
		if totalFail > 0 {
			os.Exit(1)
		}
		return
	}

	fmt.Printf("\n--- Batch Replay Summary ---\n")
	fmt.Printf("%d passed, %d failed, %d skipped\n", totalPass, totalFail, totalSkip)
	if totalFail > 0 {
		fmt.Println("\nFailed claims:")
		for _, r := range allResults {
			if !r.Pass && !r.Skipped {
				fmt.Printf("  FAIL  %s: %s\n", r.ClaimID, r.FailReason)
			}
		}
		os.Exit(1)
	}
}
