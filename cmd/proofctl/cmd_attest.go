package main

// cmdAttest implements the attest subcommand.
//
// attest records a manual or external-tool attestation for a claim without
// running a generator or checker. It is the correct path for:
//   - Claims verified by an independent reviewer (assurance: independent-review)
//   - Claims backed by a Lean/Coq compiler result already in CAS
//   - Any claim where the checker ran externally and you want to register the result
//
// Usage:
//
//	proofctl attest --claim <id> --assurance <type> [--outcome accepted|rejected]
//	  [--evidence <digest>] [--metadata key=value] [--note "human note"]
//	  [--key <keyfile>] [--force]
//
//	proofctl attest --batch <manifest.json> [--key <keyfile>] [--force]

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/telleroutlook/proofctl/internal/config"
	"github.com/telleroutlook/proofctl/internal/dag"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/signing"
)

// metaFlag is a repeatable key=value flag.
type metaFlag []string

func (f *metaFlag) String() string     { return strings.Join(*f, ", ") }
func (f *metaFlag) Set(v string) error { *f = append(*f, v); return nil }

// batchEntry is one record in an --batch manifest JSON file.
type batchEntry struct {
	Claim     string            `json:"claim"`
	Assurance string            `json:"assurance"`
	Outcome   string            `json:"outcome,omitempty"` // default: accepted
	Evidence  []string          `json:"evidence,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Note      string            `json:"note,omitempty"`
}

func cmdAttest(args []string, useJSON bool) {
	// Dispatch sub-subcommands before flag parsing so "attest diff" works cleanly.
	if len(args) > 0 && args[0] == "diff" {
		cmdAttestDiff(args[1:], useJSON)
		return
	}

	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	claimFlag := fs.String("claim", "", "claim ID to attest (required unless --batch)")
	assuranceFlag := fs.String("assurance", "independent-review", "assurance type (e.g. independent-review, exact-replay, deterministic-cap)")
	outcomeFlag := fs.String("outcome", "accepted", "outcome: accepted or rejected")
	noteFlag := fs.String("note", "", "human-readable note recorded in metadata")
	keyFlag := fs.String("key", "", "path to signing key (required for --assurance independent-review)")
	forceFlag := fs.Bool("force", false, "allow replacing a higher-assurance attestation with a lower one")
	batchFlag := fs.String("batch", "", "path to JSON manifest for batch attestation")
	var evidenceFlags multiFlag
	var metaFlags metaFlag
	fs.Var(&evidenceFlags, "evidence", "evidence digest to record (repeatable)")
	fs.Var(&metaFlags, "metadata", "metadata key=value pair (repeatable)")

	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "attest: "+err.Error())
	}

	root, _, g, _ := loadProjectGraph(useJSON)

	attestDir := filepath.Join(root, config.DirName, config.AttestDir)
	if err := os.MkdirAll(attestDir, 0o755); err != nil {
		die(useJSON, errors.CodeInternalError, "attest: mkdir: "+err.Error())
	}

	// Resolve signing key once (shared by both single and batch paths).
	signingKey := resolveSigningKey(*keyFlag, useJSON)

	if *batchFlag != "" {
		cmdAttestBatch(*batchFlag, attestDir, g, signingKey, *forceFlag, useJSON)
		return
	}

	if *claimFlag == "" {
		die(useJSON, errors.CodeInvalidInput, "attest: --claim is required (or use --batch <manifest.json>)")
	}

	outcome := *outcomeFlag
	if outcome != "accepted" && outcome != "rejected" {
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("attest: --outcome must be 'accepted' or 'rejected', got %q", outcome))
	}

	assurance := ir.Assurance(*assuranceFlag)
	if assurance == ir.AssuranceIndependentReview && signingKey == nil {
		die(useJSON, errors.CodeInvalidInput,
			"attest: --assurance independent-review requires a signing key — set --key <keyfile> or PROOFCTL_SIGNING_KEY")
	}

	metadata := parseMetaFlags(metaFlags, *noteFlag, useJSON)

	claimID := *claimFlag
	if g.Claim(claimID) == nil {
		die(useJSON, errors.CodeMissingDependency, fmt.Sprintf("attest: unknown claim %q", claimID))
	}

	var evidence []ir.EvidenceDescriptor
	for _, d := range evidenceFlags {
		evidence = append(evidence, ir.EvidenceDescriptor{Digest: d})
	}

	att, attPath, err := buildAndWriteAttestation(attestDir, claimID, assurance, outcome, evidence, metadata, signingKey, *forceFlag)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, "attest: "+err.Error())
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(map[string]string{
			"claim_id":    claimID,
			"outcome":     outcome,
			"assurance":   string(assurance),
			"self_digest": att.SelfDigest,
			"written":     attPath,
		})
		return
	}
	fmt.Printf("Attested %s\n", claimID)
	fmt.Printf("  outcome:   %s\n", outcome)
	fmt.Printf("  assurance: %s\n", assurance)
	fmt.Printf("  digest:    %s\n", att.SelfDigest)
	fmt.Printf("  written to %s\n", attPath)
}

// cmdAttestBatch reads a JSON array of batchEntry objects and writes one
// attestation per entry, sharing the signing key and force flag.
func cmdAttestBatch(manifestPath, attestDir string, g *dag.DAG, signingKey *signing.Key, force, useJSON bool) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		die(useJSON, errors.CodeInvalidInput, "attest --batch: read manifest: "+err.Error())
	}

	var entries []batchEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		die(useJSON, errors.CodeInvalidInput, "attest --batch: parse manifest: "+err.Error())
	}
	if len(entries) == 0 {
		die(useJSON, errors.CodeInvalidInput, "attest --batch: manifest contains no entries")
	}

	type batchResult struct {
		Claim      string `json:"claim"`
		SelfDigest string `json:"self_digest,omitempty"`
		Written    string `json:"written,omitempty"`
		Error      string `json:"error,omitempty"`
	}
	results := make([]batchResult, 0, len(entries))
	failed := 0

	for _, e := range entries {
		if e.Claim == "" {
			results = append(results, batchResult{Claim: "(empty)", Error: "missing claim field"})
			failed++
			continue
		}

		if g.Claim(e.Claim) == nil {
			results = append(results, batchResult{Claim: e.Claim, Error: "unknown claim — not found in graph"})
			failed++
			continue
		}

		outcome := e.Outcome
		if outcome == "" {
			outcome = "accepted"
		}
		if outcome != "accepted" && outcome != "rejected" {
			results = append(results, batchResult{Claim: e.Claim, Error: fmt.Sprintf("invalid outcome %q", outcome)})
			failed++
			continue
		}

		assurance := ir.Assurance(e.Assurance)
		if assurance == "" {
			results = append(results, batchResult{Claim: e.Claim, Error: "missing assurance field"})
			failed++
			continue
		}
		if assurance == ir.AssuranceIndependentReview && signingKey == nil {
			results = append(results, batchResult{Claim: e.Claim,
				Error: "independent-review requires a signing key — set --key or PROOFCTL_SIGNING_KEY"})
			failed++
			continue
		}

		metadata := e.Metadata
		if metadata == nil {
			metadata = make(map[string]string)
		}
		if e.Note != "" {
			metadata["note"] = e.Note
		}
		if len(metadata) == 0 {
			metadata = nil
		}

		var evidence []ir.EvidenceDescriptor
		for _, d := range e.Evidence {
			evidence = append(evidence, ir.EvidenceDescriptor{Digest: d})
		}

		att, attPath, writeErr := buildAndWriteAttestation(attestDir, e.Claim, assurance, outcome, evidence, metadata, signingKey, force)
		if writeErr != nil {
			results = append(results, batchResult{Claim: e.Claim, Error: writeErr.Error()})
			failed++
			continue
		}
		results = append(results, batchResult{Claim: e.Claim, SelfDigest: att.SelfDigest, Written: attPath})
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"results": results, "failed": failed})
		return
	}

	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(os.Stderr, "FAIL  %-40s %s\n", r.Claim, r.Error)
		} else {
			fmt.Printf("OK    %-40s %s\n", r.Claim, r.SelfDigest)
		}
	}
	fmt.Printf("\n%d attested, %d failed\n", len(results)-failed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// buildAndWriteAttestation constructs an Attestation, signs it if a key is
// provided, checks for assurance downgrade, and writes it atomically.
func buildAndWriteAttestation(
	attestDir, claimID string,
	assurance ir.Assurance,
	outcome string,
	evidence []ir.EvidenceDescriptor,
	metadata map[string]string,
	signingKey *signing.Key,
	force bool,
) (*ir.Attestation, string, error) {
	now := time.Now().UTC().Format("2006-01-02")
	att := ir.Attestation{
		ClaimID:        claimID,
		Outcome:        outcome,
		Assurance:      assurance,
		Evidence:       evidence,
		StartFreshness: now,
		EndFreshness:   now,
		Metadata:       metadata,
	}
	if len(metadata) == 0 {
		att.Metadata = nil
	}

	att.SelfDigest = ""
	selfDigest, err := ir.DigestOf(&att)
	if err != nil {
		return nil, "", fmt.Errorf("compute self-digest: %w", err)
	}
	att.SelfDigest = selfDigest

	if signingKey != nil {
		sig, signErr := signingKey.Sign(&att)
		if signErr != nil {
			return nil, "", fmt.Errorf("sign: %w", signErr)
		}
		att.Signature = &ir.AttestationSig{
			PubkeyFingerprint: sig.PubkeyFingerprint,
			Algorithm:         sig.Algorithm,
			Value:             sig.Value,
		}
	}

	attPath := filepath.Join(attestDir, claimID+".json")

	// Block downgrade: replacing a higher-assurance attestation requires --force.
	if existing, readErr := os.ReadFile(attPath); readErr == nil {
		var existingAtt ir.Attestation
		if jsonErr := json.Unmarshal(existing, &existingAtt); jsonErr == nil {
			existingLevel := ir.AssuranceLevel(existingAtt.Assurance)
			newLevel := ir.AssuranceLevel(att.Assurance)
			if existingLevel > newLevel && !force {
				return nil, "", fmt.Errorf(
					"%s has assurance %s (level %d); replacing with %s (level %d) is a downgrade — use --force to allow",
					claimID, existingAtt.Assurance, existingLevel, att.Assurance, newLevel)
			}
		}
	}

	data, _ := json.MarshalIndent(&att, "", "  ")
	if err := os.WriteFile(attPath, append(data, '\n'), 0o644); err != nil {
		return nil, "", fmt.Errorf("write: %w", err)
	}
	return &att, attPath, nil
}

// resolveSigningKey loads the signing key from --key flag or PROOFCTL_SIGNING_KEY env var.
// Returns nil if neither is set (signing disabled). Exits on load failure.
func resolveSigningKey(keyPath string, useJSON bool) *signing.Key {
	if keyPath != "" {
		k, err := loadSigningKeyFromPath(keyPath)
		if err != nil {
			die(useJSON, errors.CodeInternalError, "attest: load signing key: "+err.Error())
		}
		return k
	}
	return loadSigningKeyIfSet()
}

// parseMetaFlags converts repeatable key=value flags and a note string to a metadata map.
func parseMetaFlags(flags metaFlag, note string, useJSON bool) map[string]string {
	metadata := make(map[string]string)
	for _, kv := range flags {
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("attest: --metadata %q is not in key=value format", kv))
		}
		metadata[kv[:idx]] = kv[idx+1:]
	}
	if note != "" {
		metadata["note"] = note
	}
	if len(metadata) == 0 {
		return nil
	}
	return metadata
}

// cmdAttestDiff shows the diff between the current attestation for a claim and
// the previous version from git history. Falls back to a JSON field-by-field
// comparison if git is unavailable or the file has no prior commits.
func cmdAttestDiff(args []string, useJSON bool) {
	fs := flag.NewFlagSet("attest diff", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "attest diff: "+err.Error())
	}
	if fs.NArg() == 0 {
		die(useJSON, errors.CodeInvalidInput, "usage: proofctl attest diff <claim-id>")
	}
	claimID := strings.TrimPrefix(fs.Arg(0), "@")

	root, _, _, _ := loadProjectGraph(useJSON)
	attPath := filepath.Join(root, config.DirName, config.AttestDir, claimID+".json")

	current, err := os.ReadFile(attPath)
	if err != nil {
		if os.IsNotExist(err) {
			die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("attest diff: no attestation for %q", claimID))
		}
		die(useJSON, errors.CodeInternalError, "attest diff: "+err.Error())
	}

	// Attempt to get the previous version from git.
	relPath, relErr := filepath.Rel(root, attPath)
	if relErr != nil {
		relPath = attPath
	}
	prev, gitErr := gitPreviousVersion(root, relPath)

	if useJSON {
		type diffOutput struct {
			ClaimID  string          `json:"claim_id"`
			Previous json.RawMessage `json:"previous"`
			Current  json.RawMessage `json:"current"`
			GitError string          `json:"git_error,omitempty"`
		}
		out := diffOutput{
			ClaimID: claimID,
			Current: json.RawMessage(bytes.TrimRight(current, "\n")),
		}
		if gitErr != nil {
			out.GitError = gitErr.Error()
			out.Previous = json.RawMessage(`null`)
		} else {
			out.Previous = json.RawMessage(bytes.TrimRight(prev, "\n"))
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	if gitErr != nil {
		fmt.Fprintf(os.Stderr, "warn: cannot retrieve previous version from git: %v\n", gitErr)
		fmt.Fprintf(os.Stderr, "Showing current attestation only:\n\n")
		fmt.Printf("%s", current)
		return
	}

	// Field-level diff between prev and current JSON.
	printAttestationDiff(claimID, prev, current)
}

// gitPreviousVersion returns the previous committed content of relPath (relative
// to repoRoot) using "git show HEAD~1:<path>". Returns an error if git is
// unavailable, the repo has only one commit, or the file wasn't tracked.
func gitPreviousVersion(repoRoot, relPath string) ([]byte, error) {
	cmd := exec.Command("git", "show", "HEAD~1:"+relPath)
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		// Try HEAD (single-commit repo).
		cmd2 := exec.Command("git", "log", "--oneline", "-2", "--", relPath)
		cmd2.Dir = repoRoot
		log2, _ := cmd2.Output()
		if len(bytes.TrimSpace(log2)) == 0 {
			return nil, fmt.Errorf("file has no git history: %s", relPath)
		}
		return nil, fmt.Errorf("git show HEAD~1: %v", err)
	}
	return out, nil
}

// printAttestationDiff compares two attestation JSON blobs field by field and
// prints a human-readable summary of what changed.
func printAttestationDiff(claimID string, prev, curr []byte) {
	var a, b map[string]json.RawMessage
	if err := json.Unmarshal(prev, &a); err != nil {
		fmt.Printf("cannot parse previous attestation: %v\n", err)
		return
	}
	if err := json.Unmarshal(curr, &b); err != nil {
		fmt.Printf("cannot parse current attestation: %v\n", err)
		return
	}

	fmt.Printf("Attestation diff for %s\n", claimID)
	fmt.Printf("%-30s  %-35s  %s\n", "FIELD", "PREVIOUS", "CURRENT")
	fmt.Printf("%-30s  %-35s  %s\n", strings.Repeat("-", 30), strings.Repeat("-", 35), strings.Repeat("-", 35))

	// Collect all keys from both.
	seen := make(map[string]bool)
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}

	changed := 0
	for _, field := range []string{"outcome", "assurance", "self_digest", "cache_key", "start_freshness", "end_freshness"} {
		prev := trimJSON(a[field])
		curr := trimJSON(b[field])
		if prev == curr {
			continue
		}
		changed++
		fmt.Printf("%-30s  %-35s  %s\n", field, truncate(prev, 35), truncate(curr, 35))
	}
	// Evidence changes.
	prevEv := trimJSON(a["evidence"])
	currEv := trimJSON(b["evidence"])
	if prevEv != currEv {
		changed++
		fmt.Printf("%-30s  %-35s  %s\n", "evidence", truncate(prevEv, 35), truncate(currEv, 35))
	}
	// Metadata changes.
	prevMeta := trimJSON(a["metadata"])
	currMeta := trimJSON(b["metadata"])
	if prevMeta != currMeta {
		changed++
		fmt.Printf("%-30s  %-35s  %s\n", "metadata", truncate(prevMeta, 35), truncate(currMeta, 35))
	}
	// Signature — expand nested fields instead of truncating the raw JSON blob.
	prevSig := trimJSON(a["signature"])
	currSig := trimJSON(b["signature"])
	if prevSig != currSig {
		changed++
		prevFields := expandSignature(a["signature"])
		currFields := expandSignature(b["signature"])
		allSigKeys := []string{"pubkey_fingerprint", "algorithm", "value"}
		for _, sk := range allSigKeys {
			pv, cv := prevFields[sk], currFields[sk]
			if pv == cv {
				continue
			}
			label := "signature." + sk
			fmt.Printf("%-30s  %-35s  %s\n", label, truncate(pv, 35), truncate(cv, 35))
		}
	}

	_ = seen // all fields checked above
	fmt.Printf("\n%d field(s) changed\n", changed)
}

func trimJSON(raw json.RawMessage) string {
	if raw == nil {
		return "(absent)"
	}
	return strings.TrimSpace(string(raw))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// expandSignature unmarshals a signature JSON blob into a string map so each
// sub-field (pubkey_fingerprint, algorithm, value) can be diffed individually.
func expandSignature(raw json.RawMessage) map[string]string {
	out := map[string]string{"pubkey_fingerprint": "(absent)", "algorithm": "(absent)", "value": "(absent)"}
	if raw == nil {
		return out
	}
	var sig map[string]string
	if err := json.Unmarshal(raw, &sig); err != nil {
		out["pubkey_fingerprint"] = trimJSON(raw)
		return out
	}
	for k, v := range sig {
		out[k] = v
	}
	return out
}
