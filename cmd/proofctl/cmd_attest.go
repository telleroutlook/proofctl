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

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/telleroutlook/proofctl/internal/config"
	errors "github.com/telleroutlook/proofctl/internal/errors"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// metaFlag is a repeatable key=value flag.
type metaFlag []string

func (f *metaFlag) String() string     { return strings.Join(*f, ", ") }
func (f *metaFlag) Set(v string) error { *f = append(*f, v); return nil }

func cmdAttest(args []string, useJSON bool) {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	claimFlag := fs.String("claim", "", "claim ID to attest (required)")
	assuranceFlag := fs.String("assurance", "independent-review", "assurance type (e.g. independent-review, exact-replay, deterministic-cap)")
	outcomeFlag := fs.String("outcome", "accepted", "outcome: accepted or rejected")
	noteFlag := fs.String("note", "", "human-readable note recorded in metadata")
	var evidenceFlags multiFlag
	var metaFlags metaFlag
	fs.Var(&evidenceFlags, "evidence", "evidence digest to record (repeatable)")
	fs.Var(&metaFlags, "metadata", "metadata key=value pair (repeatable)")

	if err := fs.Parse(args); err != nil {
		die(useJSON, errors.CodeInvalidInput, "attest: "+err.Error())
	}

	if *claimFlag == "" {
		die(useJSON, errors.CodeInvalidInput, "attest: --claim is required")
	}
	claimID := *claimFlag

	outcome := *outcomeFlag
	if outcome != "accepted" && outcome != "rejected" {
		die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("attest: --outcome must be 'accepted' or 'rejected', got %q", outcome))
	}

	root, _, g, _ := loadProjectGraph(useJSON)

	if g.Claim(claimID) == nil {
		die(useJSON, errors.CodeMissingDependency, fmt.Sprintf("attest: unknown claim %q", claimID))
	}

	// Parse metadata flags.
	metadata := make(map[string]string)
	for _, kv := range metaFlags {
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			die(useJSON, errors.CodeInvalidInput, fmt.Sprintf("attest: --metadata %q is not in key=value format", kv))
		}
		metadata[kv[:idx]] = kv[idx+1:]
	}
	if *noteFlag != "" {
		metadata["note"] = *noteFlag
	}

	// Build evidence descriptors from the digests provided.
	var evidence []ir.EvidenceDescriptor
	for _, d := range evidenceFlags {
		evidence = append(evidence, ir.EvidenceDescriptor{Digest: d})
	}

	now := time.Now().UTC().Format("2006-01-02")
	att := ir.Attestation{
		ClaimID:        claimID,
		Outcome:        outcome,
		Assurance:      ir.Assurance(*assuranceFlag),
		Evidence:       evidence,
		StartFreshness: now,
		EndFreshness:   now,
		Metadata:       metadata,
	}
	if len(metadata) == 0 {
		att.Metadata = nil
	}

	// Compute self-digest.
	att.SelfDigest = ""
	selfDigest, err := ir.DigestOf(&att)
	if err != nil {
		die(useJSON, errors.CodeInternalError, "attest: compute self-digest: "+err.Error())
	}
	att.SelfDigest = selfDigest

	// Optionally sign.
	if key := loadSigningKeyIfSet(); key != nil {
		sig, signErr := key.Sign(&att)
		if signErr != nil {
			die(useJSON, errors.CodeInternalError, "attest: sign: "+signErr.Error())
		}
		att.Signature = &ir.AttestationSig{
			PubkeyFingerprint: sig.PubkeyFingerprint,
			Algorithm:         sig.Algorithm,
			Value:             sig.Value,
		}
	}

	attestDir := filepath.Join(root, config.DirName, config.AttestDir)
	if err := os.MkdirAll(attestDir, 0o755); err != nil {
		die(useJSON, errors.CodeInternalError, "attest: mkdir: "+err.Error())
	}
	attPath := filepath.Join(attestDir, claimID+".json")

	// Warn if overwriting a higher-assurance attestation.
	if existing, readErr := os.ReadFile(attPath); readErr == nil {
		var existingAtt ir.Attestation
		if jsonErr := json.Unmarshal(existing, &existingAtt); jsonErr == nil {
			if isHigherAssurance(existingAtt.Assurance) && existingAtt.Assurance != att.Assurance {
				if !useJSON {
					fmt.Fprintf(os.Stderr, "warn: overwriting %s attestation with %s for %s\n",
						existingAtt.Assurance, att.Assurance, claimID)
				}
			}
		}
	}

	data, _ := json.MarshalIndent(&att, "", "  ")
	if err := os.WriteFile(attPath, append(data, '\n'), 0o644); err != nil {
		die(useJSON, errors.CodeInternalError, "attest: write: "+err.Error())
	}

	if useJSON {
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(map[string]string{
			"claim_id":    claimID,
			"outcome":     outcome,
			"assurance":   *assuranceFlag,
			"self_digest": att.SelfDigest,
			"written":     attPath,
		})
		return
	}
	fmt.Printf("Attested %s\n", claimID)
	fmt.Printf("  outcome:   %s\n", outcome)
	fmt.Printf("  assurance: %s\n", *assuranceFlag)
	fmt.Printf("  digest:    %s\n", att.SelfDigest)
	fmt.Printf("  written to %s\n", attPath)
}
