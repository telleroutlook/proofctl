// Package policy defines the v2 release policy types for the proofverify kernel.
//
// PolicyV2 declares which signing keys are authorized to produce which assurance
// types for which claim kinds and runtimes. The kernel enforces this at release
// time — attestations signed by unauthorized keys are rejected (INV-04).
//
// PolicyV2 is separate from the v1 policy.ReleasePolicy and lives inside
// internal/kernel so proofverify can use it without importing the orchestrator.
package policy

// KeyAuth declares what a specific signing key is authorized to attest.
type KeyAuth struct {
	// KeyFingerprint is sha256(raw_ed25519_public_key_bytes) as hex.
	KeyFingerprint string `json:"key_fingerprint"`

	// AllowedRoles lists the roles this key may hold (e.g. "checker", "release-authority").
	AllowedRoles []string `json:"allowed_roles"`

	// AllowedAssurances lists the assurance types this key may produce.
	// An empty list means the key has no assurance-signing rights.
	AllowedAssurances []string `json:"allowed_assurances"`

	// AllowedClaimKinds lists the claim kinds this key may attest.
	// An empty list means the key is authorized for all claim kinds.
	AllowedClaimKinds []string `json:"allowed_claim_kinds,omitempty"`

	// AllowedRuntimes lists the runtime classes this key may attest.
	// An empty list means the key is authorized for all runtimes.
	AllowedRuntimes []string `json:"allowed_runtimes,omitempty"`
}

// PolicyV2 is the v2 release policy consumed by proofverify.
type PolicyV2 struct {
	Version string `json:"version"`
	Target  string `json:"target"` // root claim ID for release

	// SigningKeyAuthorizations declares the trust model: which keys can sign
	// which assurances for which claims (INV-04).
	SigningKeyAuthorizations []KeyAuth `json:"signing_key_authorizations"`

	// RequiredAssurances maps claim kinds to the assurance types required
	// before a claim of that kind may contribute to release.
	// Key: claim kind (e.g. "theorem", "lemma"). Value: required assurance types.
	RequiredAssurances map[string][]string `json:"required_assurances,omitempty"`

	// ForbiddenRuntimes lists runtime classes that must not appear in any
	// attestation that contributes to release (e.g. "native-dev" → INV-10).
	ForbiddenRuntimes []string `json:"forbidden_runtimes,omitempty"`

	// RequiredReplayMode, if set, requires all attestations to record this
	// replay mode (e.g. "semantic" or "byte_exact").
	RequiredReplayMode string `json:"required_replay_mode,omitempty"`
}

// IsKeyAuthorizedFor returns true if the given key fingerprint is authorized
// to produce an attestation with the given assurance for the given claim kind
// and runtime class. Returns false if the fingerprint is not found.
func (p *PolicyV2) IsKeyAuthorizedFor(fingerprint, assurance, claimKind, runtimeClass string) bool {
	for _, ka := range p.SigningKeyAuthorizations {
		if ka.KeyFingerprint != fingerprint {
			continue
		}
		if !containsOrEmpty(ka.AllowedAssurances, assurance) {
			continue
		}
		if !containsOrEmpty(ka.AllowedClaimKinds, claimKind) {
			continue
		}
		if !containsOrEmpty(ka.AllowedRuntimes, runtimeClass) {
			continue
		}
		return true
	}
	return false
}

// IsForbiddenRuntime returns true if runtimeClass appears in ForbiddenRuntimes (INV-10).
func (p *PolicyV2) IsForbiddenRuntime(runtimeClass string) bool {
	for _, r := range p.ForbiddenRuntimes {
		if r == runtimeClass {
			return true
		}
	}
	return false
}

func containsOrEmpty(list []string, val string) bool {
	if len(list) == 0 {
		return true
	}
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}
