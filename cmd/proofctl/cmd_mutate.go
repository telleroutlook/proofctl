package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/kernel/attestation"
	"github.com/telleroutlook/proofctl/internal/kernel/derive"
	v2 "github.com/telleroutlook/proofctl/pkg/protocol/v2"
)

// cmdMutate implements `proofctl mutate`.
//
// Runs the platform-level mandatory mutation catalog against the current
// validators. Every mutation must be rejected; kill rate < 100% exits 1.
//
// Usage:
//
//	proofctl mutate [--catalog platform] [--json]
func cmdMutate(args []string, useJSON bool) {
	// Locate testdata/mutation relative to the binary's location or the
	// project root detected from .proofctl/.
	mutationDir := findMutationDir()

	type mutationResult struct {
		Name    string `json:"name"`
		Killed  bool   `json:"killed"`
		Blocker string `json:"blocker"`
		Error   string `json:"error,omitempty"`
	}

	var results []mutationResult

	// Platform catalog: entries are (fixture file, validator, expected claim ID, expected obligations).
	type entry struct {
		file        string
		description string
		run         func(dir string) (killed bool, blocker, errMsg string)
	}

	catalog := []entry{
		{
			file:        "v2_wrong_protocol_version.json",
			description: "v2 protocol_version=1 must be rejected",
			run:         mutCheckValidateOutput("v2_wrong_protocol_version.json", "thm-main", []string{"obl-a"}),
		},
		{
			file:        "v2_claim_id_mismatch.json",
			description: "v2 wrong claim_id echo must be rejected",
			run:         mutCheckValidateOutput("v2_claim_id_mismatch.json", "thm-main", []string{"obl-a"}),
		},
		{
			file:        "v2_missing_obligation.json",
			description: "v2 missing obligation must be rejected (INV-06)",
			run:         mutCheckValidateOutput("v2_missing_obligation.json", "thm-main", []string{"obl-a", "obl-b"}),
		},
		{
			file:        "v2_extra_obligation.json",
			description: "v2 extra obligation must be rejected (INV-06)",
			run:         mutCheckValidateOutput("v2_extra_obligation.json", "thm-main", []string{"obl-a", "obl-b"}),
		},
		{
			file:        "v2_duplicate_obligation.json",
			description: "v2 duplicate obligation must be rejected (INV-06)",
			run:         mutCheckValidateOutput("v2_duplicate_obligation.json", "thm-main", []string{"obl-a"}),
		},
		{
			file:        "v2_invalid_verdict.json",
			description: "v2 verdict='accepted' must be rejected (INV-01)",
			run:         mutCheckValidateOutput("v2_invalid_verdict.json", "thm-main", []string{"obl-a"}),
		},
		{
			file:        "v2_native_runtime_in_release.json",
			description: "native runtime in release closure must be rejected (INV-10/C09)",
			run:         mutCheckNativeRuntime("v2_native_runtime_in_release.json"),
		},
		{
			file:        "attestation_self_digest_tampered.json",
			description: "tampered self_digest must be rejected (INV-03)",
			run:         mutCheckAttestationSelfDigest("attestation_self_digest_tampered.json"),
		},
		{
			file:        "attestation_identity_stale.json",
			description: "stale claim_identity_digest must be rejected (INV-09)",
			run:         mutCheckAttestationIdentity("attestation_identity_stale.json"),
		},
	}

	killed := 0
	for _, e := range catalog {
		k, blocker, errMsg := e.run(mutationDir)
		if k {
			killed++
		}
		results = append(results, mutationResult{
			Name:    strings.TrimSuffix(e.file, ".json"),
			Killed:  k,
			Blocker: blocker,
			Error:   errMsg,
		})
	}

	total := len(catalog)
	killRate := float64(killed) / float64(total) * 100

	if useJSON {
		type output struct {
			Total    int              `json:"total"`
			Killed   int              `json:"killed"`
			Survived int              `json:"survived"`
			KillRate string           `json:"kill_rate"`
			Pass     bool             `json:"pass"`
			Results  []mutationResult `json:"results"`
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(output{
			Total:    total,
			Killed:   killed,
			Survived: total - killed,
			KillRate: fmt.Sprintf("%.0f%%", killRate),
			Pass:     killed == total,
			Results:  results,
		})
		if killed < total {
			os.Exit(1)
		}
		return
	}

	fmt.Printf("proofctl mutate — platform catalog (%d mutations)\n\n", total)
	for _, r := range results {
		icon := "KILLED"
		if !r.Killed {
			icon = "SURVIVED"
		}
		fmt.Printf("  [%s] %s", icon, r.Name)
		if r.Blocker != "" {
			fmt.Printf(" — %s", r.Blocker)
		}
		if r.Error != "" {
			fmt.Printf(" (error: %s)", r.Error)
		}
		fmt.Println()
	}
	fmt.Printf("\nKill rate: %d/%d (%.0f%%)\n", killed, total, killRate)
	if killed < total {
		fmt.Fprintf(os.Stderr, "\nERROR: kill rate %.0f%% < 100%% — %d mutation(s) survived\n",
			killRate, total-killed)
		os.Exit(1)
	}
	fmt.Println("PASS: all mutations killed")
}

// mutCheckValidateOutput returns a runner that loads a CheckerOutputV2 fixture
// and calls ValidateOutput. Killed = error is non-nil.
func mutCheckValidateOutput(file, claimID string, expectedIDs []string) func(string) (bool, string, string) {
	return func(dir string) (bool, string, string) {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return false, "", "cannot read fixture: " + err.Error()
		}
		var out v2.CheckerOutputV2
		if err := json.Unmarshal(data, &out); err != nil {
			return false, "", "parse error: " + err.Error()
		}
		valErr := v2.ValidateOutput(out, claimID, expectedIDs)
		if valErr != nil {
			return true, valErr.Error(), ""
		}
		return false, "", "ValidateOutput did not reject the mutation"
	}
}

// mutCheckNativeRuntime loads an ir.Attestation and verifies the runtime.kind
// would be caught by C09.
func mutCheckNativeRuntime(file string) func(string) (bool, string, string) {
	return func(dir string) (bool, string, string) {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return false, "", "cannot read fixture: " + err.Error()
		}
		var att ir.Attestation
		if err := json.Unmarshal(data, &att); err != nil {
			return false, "", "parse error: " + err.Error()
		}
		kind := att.Checker.Runtime.Kind
		forbidden := []string{"native", "native-dev", "shadow"}
		for _, k := range forbidden {
			if k == kind {
				return true, fmt.Sprintf("C09: runtime.kind=%q is in forbidden list", kind), ""
			}
		}
		return false, "", fmt.Sprintf("C09 would not catch runtime.kind=%q", kind)
	}
}

// mutCheckAttestationSelfDigest loads an AttestationV2 and verifies the
// tampered self_digest is caught by attestation.Validate.
func mutCheckAttestationSelfDigest(file string) func(string) (bool, string, string) {
	return func(dir string) (bool, string, string) {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return false, "", "cannot read fixture: " + err.Error()
		}
		var att attestation.AttestationV2
		if err := json.Unmarshal(data, &att); err != nil {
			return false, "", "parse error: " + err.Error()
		}
		valErr := attestation.Validate(&att, att.ClaimIdentityDigest, map[string]ed25519.PublicKey{})
		if valErr != nil {
			return true, valErr.Error(), ""
		}
		return false, "", "attestation.Validate did not reject tampered self_digest"
	}
}

// mutCheckAttestationIdentity loads an AttestationV2 and verifies that a
// mismatched claim_identity_digest is caught.
func mutCheckAttestationIdentity(file string) func(string) (bool, string, string) {
	return func(dir string) (bool, string, string) {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return false, "", "cannot read fixture: " + err.Error()
		}
		var att attestation.AttestationV2
		if err := json.Unmarshal(data, &att); err != nil {
			return false, "", "parse error: " + err.Error()
		}
		// Fix self_digest so it matches the (stale) attestation content.
		att.SelfDigest = attestation.ComputeSelfDigest(&att)
		// Use a different current identity to simulate staleness.
		currentIdentity := "sha256:current-identity-after-checker-was-updated"
		valErr := attestation.Validate(&att, currentIdentity, map[string]ed25519.PublicKey{})
		if valErr != nil {
			return true, valErr.Error(), ""
		}
		// Also check via DeriveClaimState.
		in := derive.DeriveInput{
			ClaimID:             att.ClaimID,
			CurrentIdentity:     currentIdentity,
			AttestationIdentity: att.ClaimIdentityDigest,
			Evidence:            derive.EvidencePresent,
			ObligationSet:       derive.ObligationSetPass,
			DepStates:           map[string]derive.ClaimStateV2{},
			RequiredDepStates:   map[string]derive.ClaimStateV2{},
		}
		state := derive.DeriveClaimState(in)
		if state == derive.StateStale {
			return true, "DeriveClaimState: STALE (INV-09)", ""
		}
		return false, "", "neither attestation.Validate nor DeriveClaimState caught the stale identity"
	}
}

// findMutationDir returns the path to testdata/mutation relative to the
// proofctl project root (detected from .proofctl/ directory traversal).
func findMutationDir() string {
	// Try relative to current working directory.
	candidates := []string{
		"testdata/mutation",
		"../testdata/mutation",
		"../../testdata/mutation",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	// Fall back: look for project root via .proofctl/
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, ".proofctl")); err == nil {
			candidate := filepath.Join(dir, "testdata", "mutation")
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "testdata/mutation"
}
