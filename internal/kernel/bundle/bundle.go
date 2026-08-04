// Package bundle defines the v2 release bundle types and manifest structure.
//
// A release bundle is the single authoritative artifact produced by
// `proofctl release`. It is self-contained: proofverify can verify it
// offline without access to the source repository, network, or tool cache
// (INV-12).
//
// Bundle layout:
//
//	bundle/
//	  manifest.json          ← this package's Manifest type
//	  graph.json
//	  policy.json
//	  contracts/
//	  attestations/
//	  reviews/
//	  evidence/sha256/...
//	  identities/
//	    checkers.json
//	    runtimes.json
//	    toolchains.json
//	  replay/
//	    semantic-results.json
//	    byte-results.json
//	  mutation/results.json
//	  signatures/
package bundle

// ManifestMemberDigest records one bundle member and its content digest.
type ManifestMemberDigest struct {
	Path   string `json:"path"`
	Digest string `json:"digest"` // "sha256:<hex>"
}

// Manifest is the root document of a release bundle.
// It binds all members to a root claim, graph root, policy, and state
// derivation version. The manifest itself is signed by the release authority.
//
// INV-12: proofverify must be able to verify the bundle using only this
// manifest plus the member files — no external state or network access allowed.
type Manifest struct {
	FormatVersion string `json:"format_version"` // "2"

	// RootClaim is the ID of the claim that must reach RELEASED for this bundle
	// to be valid.
	RootClaim string `json:"root_claim"`

	// GraphRootDigest is the sha256 of graph.json included in this bundle.
	GraphRootDigest string `json:"graph_root_digest"`

	// PolicyDigest is the sha256 of policy.json included in this bundle.
	PolicyDigest string `json:"policy_digest"`

	// StateDerivationVersion identifies the proofverify rule version used.
	// Any change to the state machine requires a version bump here.
	StateDerivationVersion string `json:"state_derivation_version"`

	// Members lists all files in the bundle with their content digests.
	// proofverify must verify every entry before processing.
	Members []ManifestMemberDigest `json:"members"`

	// ReleaseAuthority identifies the key that signed this manifest.
	ReleaseAuthority struct {
		KeyFingerprint string `json:"key_fingerprint"`
		Algorithm      string `json:"algorithm"`
		SignatureValue string `json:"signature_value"`
	} `json:"release_authority"`

	// GeneratedAt is the RFC3339 timestamp when this bundle was created.
	// Informational only; not part of the signed payload.
	GeneratedAt string `json:"generated_at,omitempty"`
}

// VerificationResult is the output of proofverify for a bundle.
type VerificationResult struct {
	// Released is the single authoritative conclusion: true iff the root claim
	// reached RELEASED under the current bundle's policy and identity closure.
	Released bool `json:"released"`

	// RootState is the derived state of the root claim.
	RootState string `json:"root_state"`

	// ClaimStates maps every claim ID in the bundle to its derived state.
	ClaimStates map[string]string `json:"claim_states"`

	// Blockers lists the specific reasons release was denied, if Released==false.
	Blockers []string `json:"blockers,omitempty"`

	// StateDerivationVersion records which rule version was used.
	StateDerivationVersion string `json:"state_derivation_version"`
}
