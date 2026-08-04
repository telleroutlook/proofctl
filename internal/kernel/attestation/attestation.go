// Package attestation defines the v2 attestation types and validation logic.
//
// A v2 attestation records the outcome of a checker invocation as a set of
// per-obligation verdicts bound to the claim's identity closure. Unlike v1,
// it does NOT contain an Outcome or Assurance field that can be set by the
// checker or by hand. All state is derived by proofverify.
//
// Validation enforces (in order):
//
//  1. SelfDigest matches sha256(attestation-sans-self_digest) — INV-03
//  2. ClaimIdentityDigest matches identity.Compute(current inputs) — INV-02
//  3. Signature verified against a trusted key from the policy — INV-04
//  4. ObligationResults non-empty — prerequisite for INV-06
package attestation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// SignatureV2 is an Ed25519 signature over the canonical attestation payload.
type SignatureV2 struct {
	PubkeyFingerprint string `json:"pubkey_fingerprint"` // sha256 hex of raw public key bytes
	Algorithm         string `json:"algorithm"`          // must be "ed25519"
	Value             string `json:"value"`              // base64-encoded signature
}

// ObligationResultV2 records one obligation's verdict in a stored attestation.
type ObligationResultV2 struct {
	ID            string `json:"id"`
	Verdict       string `json:"verdict"` // "pass" | "fail"
	WitnessDigest string `json:"witness_digest,omitempty"`
	Method        string `json:"method,omitempty"`
}

// AttestationV2 is the stored result of a v2 checker invocation.
//
// INV-01: No Outcome, Assurance, Status, or Released field exists here.
// INV-02: ClaimIdentityDigest binds this attestation to its full input closure.
// INV-03: SelfDigest is recomputed on load; mismatch causes rejection.
type AttestationV2 struct {
	ProtocolVersion int    `json:"protocol_version"` // must be 2
	ClaimID         string `json:"claim_id"`

	// ClaimIdentityDigest is the identity.Compute() result for the inputs
	// that produced this attestation (INV-02).
	ClaimIdentityDigest string `json:"claim_identity_digest"`

	// CheckerIdentityDigest is the sha256 of the checker used.
	CheckerIdentityDigest string `json:"checker_identity_digest"`

	// RuntimeIdentityDigest is the sha256 of the OCI image or runtime spec.
	RuntimeIdentityDigest string `json:"runtime_identity_digest"`

	// EvidenceUsed lists the evidence digests read during this invocation.
	EvidenceUsed []string `json:"evidence_used"`

	// ObligationResults is the per-obligation verdict set (INV-06, INV-07).
	ObligationResults []ObligationResultV2 `json:"obligation_results"`

	// Toolchain records tool version metadata from the checker output.
	Toolchain map[string]string `json:"toolchain,omitempty"`

	// StartFreshness and EndFreshness are RFC3339 timestamps bounding the run.
	StartFreshness string `json:"start_freshness"`
	EndFreshness   string `json:"end_freshness"`

	// SelfDigest is sha256(JSON of this object with self_digest omitted) — INV-03.
	SelfDigest string `json:"self_digest"`

	// Signature is optional Ed25519 signature over the canonical payload — INV-04.
	Signature *SignatureV2 `json:"signature,omitempty"`
}

// selfDigestPayload is the canonical payload for self-digest computation.
// It mirrors AttestationV2 but omits SelfDigest and Signature.
type selfDigestPayload struct {
	ProtocolVersion       int                  `json:"protocol_version"`
	ClaimID               string               `json:"claim_id"`
	ClaimIdentityDigest   string               `json:"claim_identity_digest"`
	CheckerIdentityDigest string               `json:"checker_identity_digest"`
	RuntimeIdentityDigest string               `json:"runtime_identity_digest"`
	EvidenceUsed          []string             `json:"evidence_used"`
	ObligationResults     []ObligationResultV2 `json:"obligation_results"`
	Toolchain             map[string]string    `json:"toolchain,omitempty"`
	StartFreshness        string               `json:"start_freshness"`
	EndFreshness          string               `json:"end_freshness"`
}

// ComputeSelfDigest returns the canonical self-digest of att.
// This is sha256 of the JSON of the payload excluding self_digest and signature.
func ComputeSelfDigest(att *AttestationV2) string {
	p := selfDigestPayload{
		ProtocolVersion:       att.ProtocolVersion,
		ClaimID:               att.ClaimID,
		ClaimIdentityDigest:   att.ClaimIdentityDigest,
		CheckerIdentityDigest: att.CheckerIdentityDigest,
		RuntimeIdentityDigest: att.RuntimeIdentityDigest,
		EvidenceUsed:          att.EvidenceUsed,
		ObligationResults:     att.ObligationResults,
		Toolchain:             att.Toolchain,
		StartFreshness:        att.StartFreshness,
		EndFreshness:          att.EndFreshness,
	}
	data, err := json.Marshal(p)
	if err != nil {
		panic(fmt.Sprintf("attestation: self-digest marshal: %v", err))
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}

// ValidationError describes a failed attestation validation check.
type ValidationError struct {
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("attestation [%s]: %s", e.Code, e.Message)
}

var (
	ErrSelfDigestMismatch   = errors.New("self_digest mismatch")
	ErrIdentityMismatch     = errors.New("claim_identity_digest mismatch")
	ErrSignatureInvalid     = errors.New("signature invalid")
	ErrSignatureKeyUnknown  = errors.New("signing key not in trust store")
	ErrObligationsEmpty     = errors.New("obligation_results must be non-empty")
	ErrProtocolVersionWrong = errors.New("protocol_version must be 2")
)

// Validate checks the integrity of a stored AttestationV2.
//
// Parameters:
//   - att: the attestation to validate
//   - currentIdentity: the identity digest computed from the CURRENT inputs
//     (caller must pass identity.Compute(currentInputs))
//   - trustedKeys: map from pubkey fingerprint to ed25519.PublicKey (from policy)
//
// Validation order matches INV numbering:
//  1. Protocol version
//  2. SelfDigest recomputation (INV-03)
//  3. ClaimIdentityDigest vs currentIdentity (INV-02)
//  4. Signature if present (INV-04)
//  5. ObligationResults non-empty (prerequisite for INV-06)
func Validate(att *AttestationV2, currentIdentity string, trustedKeys map[string]ed25519.PublicKey) error {
	if att.ProtocolVersion != 2 {
		return &ValidationError{Code: "PROTOCOL_VERSION", Message: fmt.Sprintf("got %d, want 2", att.ProtocolVersion)}
	}

	// INV-03: recompute and compare self-digest
	computed := ComputeSelfDigest(att)
	if computed != att.SelfDigest {
		return &ValidationError{
			Code:    "SELF_DIGEST_MISMATCH",
			Message: fmt.Sprintf("stored %q, computed %q", att.SelfDigest, computed),
		}
	}

	// INV-02: identity binding
	if currentIdentity != "" && att.ClaimIdentityDigest != currentIdentity {
		return &ValidationError{
			Code:    "IDENTITY_MISMATCH",
			Message: fmt.Sprintf("stored %q, current %q — attestation is STALE", att.ClaimIdentityDigest, currentIdentity),
		}
	}

	// INV-04: signature verification
	if att.Signature != nil {
		if err := verifySignature(att, trustedKeys); err != nil {
			return err
		}
	}

	// Prerequisite for INV-06
	if len(att.ObligationResults) == 0 {
		return &ValidationError{Code: "EMPTY_OBLIGATIONS", Message: "obligation_results must not be empty"}
	}

	return nil
}

// verifySignature verifies the Ed25519 signature in att.Signature.
func verifySignature(att *AttestationV2, trustedKeys map[string]ed25519.PublicKey) error {
	sig := att.Signature
	if sig.Algorithm != "ed25519" {
		return &ValidationError{Code: "UNKNOWN_ALGORITHM", Message: fmt.Sprintf("unsupported algorithm %q", sig.Algorithm)}
	}

	pubKey, ok := trustedKeys[sig.PubkeyFingerprint]
	if !ok {
		return &ValidationError{
			Code:    "UNKNOWN_KEY",
			Message: fmt.Sprintf("pubkey fingerprint %q not in trust store", sig.PubkeyFingerprint),
		}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return &ValidationError{Code: "SIGNATURE_DECODE", Message: fmt.Sprintf("base64 decode: %v", err)}
	}

	// Sign over the self-digest payload (same bytes used for SelfDigest).
	p := selfDigestPayload{
		ProtocolVersion:       att.ProtocolVersion,
		ClaimID:               att.ClaimID,
		ClaimIdentityDigest:   att.ClaimIdentityDigest,
		CheckerIdentityDigest: att.CheckerIdentityDigest,
		RuntimeIdentityDigest: att.RuntimeIdentityDigest,
		EvidenceUsed:          att.EvidenceUsed,
		ObligationResults:     att.ObligationResults,
		Toolchain:             att.Toolchain,
		StartFreshness:        att.StartFreshness,
		EndFreshness:          att.EndFreshness,
	}
	data, err := json.Marshal(p)
	if err != nil {
		return &ValidationError{Code: "SIGNATURE_MARSHAL", Message: fmt.Sprintf("marshal: %v", err)}
	}

	if !ed25519.Verify(pubKey, data, sigBytes) {
		return &ValidationError{Code: "SIGNATURE_INVALID", Message: "ed25519 signature does not verify"}
	}
	return nil
}
