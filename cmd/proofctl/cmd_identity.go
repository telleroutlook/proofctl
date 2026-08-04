package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/telleroutlook/proofctl/internal/kernel/identity"
)

// cmdIdentity implements `proofctl identity @<claim-id>`.
//
// It constructs the ClaimIdentityInputs for the given claim from the current
// project graph and prints the canonical identity digest along with each
// contributing field.
//
// Usage:
//
//	proofctl identity @<claim-id>
func cmdIdentity(args []string, useJSON bool) {
	if len(args) == 0 {
		die(useJSON, "INVALID_INPUT", "usage: proofctl identity @<claim-id>")
	}
	claimID := strings.TrimPrefix(args[0], "@")

	root, _, g, attestations := loadProjectGraph(useJSON)
	_ = root
	pg := loadRawGraph(root, useJSON)

	claim := g.Claim(claimID)
	if claim == nil {
		die(useJSON, "MISSING_CLAIM", "unknown claim: "+claimID)
	}

	// Collect ordered dep identities (sorted by dep claim ID for determinism).
	depIDs := make([]string, len(claim.DependsOn))
	copy(depIDs, claim.DependsOn)
	sort.Strings(depIDs)

	depIdentities := make([]string, 0, len(depIDs))
	for _, depID := range depIDs {
		depAtt, ok := attestations[depID]
		if ok && depAtt.SelfDigest != "" {
			depIdentities = append(depIdentities, depAtt.SelfDigest)
		} else {
			depIdentities = append(depIdentities, "sha256:<no-attestation-for-"+depID+">")
		}
	}

	// Collect evidence descriptors from the claim.
	evidenceDescs := make([]identity.EvidenceDescriptor, 0, len(claim.Evidence))
	for _, digest := range claim.Evidence {
		evidenceDescs = append(evidenceDescs, identity.EvidenceDescriptor{
			Digest: digest,
		})
	}

	// Look up checker identity from the raw ProofGraph.
	checkerIdentDigest := ""
	runtimeIdentDigest := ""
	if claim.CheckerPolicy != "" {
		if ch, found := findChecker(pg, claim.CheckerPolicy); found {
			checkerIdentDigest = ch.CheckerDigest
			runtimeIdentDigest = ch.Runtime.Digest
		}
	}

	inputs := identity.ClaimIdentityInputs{
		CanonicalStatement:    claim.Statement.Text,
		OrderedDepIdentities:  depIdentities,
		EvidenceDescriptors:   evidenceDescs,
		ContractDigest:        "", // populated when ContractV2 is available (M28)
		CheckerIdentityDigest: checkerIdentDigest,
		RuntimeIdentityDigest: runtimeIdentDigest,
		PolicyDigest:          "", // populated when policy digest is pinned (M28)
		GraphRootDigest:       "", // populated when graph root is pinned (M28)
	}

	digest := identity.Compute(inputs)

	if useJSON {
		type identityOutput struct {
			ClaimID string                       `json:"claim_id"`
			Digest  string                       `json:"digest"`
			Inputs  identity.ClaimIdentityInputs `json:"inputs"`
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(identityOutput{
			ClaimID: claimID,
			Digest:  digest,
			Inputs:  inputs,
		})
		return
	}

	fmt.Printf("claim:   %s\n", claimID)
	fmt.Printf("digest:  %s\n", digest)
	fmt.Println()
	fmt.Println("inputs:")
	fmt.Printf("  statement:               %s\n", identityTruncate(claim.Statement.Text, 60))
	fmt.Printf("  dep_identities (%d):      %s\n", len(depIdentities), identityJoin(depIdentities))
	fmt.Printf("  evidence (%d):           %s\n", len(evidenceDescs), identityJoinEvidence(evidenceDescs))
	fmt.Printf("  checker_identity_digest: %s\n", identityOrEmpty(checkerIdentDigest))
	fmt.Printf("  runtime_identity_digest: %s\n", identityOrEmpty(runtimeIdentDigest))
	fmt.Println("  contract_digest:         (not yet pinned — M28)")
	fmt.Println("  policy_digest:           (not yet pinned — M28)")
	fmt.Println("  graph_root_digest:       (not yet pinned — M28)")
}

func identityTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func identityJoin(ss []string) string {
	if len(ss) == 0 {
		return "(none)"
	}
	return strings.Join(ss, ", ")
}

func identityJoinEvidence(descs []identity.EvidenceDescriptor) string {
	if len(descs) == 0 {
		return "(none)"
	}
	parts := make([]string, len(descs))
	for i, d := range descs {
		parts[i] = d.Digest
	}
	return strings.Join(parts, ", ")
}

func identityOrEmpty(s string) string {
	if s == "" {
		return "(not pinned)"
	}
	return s
}
