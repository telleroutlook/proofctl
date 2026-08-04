package attestation_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/telleroutlook/proofctl/internal/kernel/attestation"
)

// baseAttestation returns a valid, self-consistent AttestationV2 with a correct SelfDigest.
func baseAttestation() *attestation.AttestationV2 {
	att := &attestation.AttestationV2{
		ProtocolVersion:       2,
		ClaimID:               "thm-main",
		ClaimIdentityDigest:   "sha256:identity111",
		CheckerIdentityDigest: "sha256:checker222",
		RuntimeIdentityDigest: "sha256:runtime333",
		EvidenceUsed:          []string{"sha256:ev444"},
		ObligationResults: []attestation.ObligationResultV2{
			{ID: "path-a.integrals", Verdict: "pass", Method: "arb-v1"},
		},
		Toolchain:      map[string]string{"python": "3.13"},
		StartFreshness: "2026-08-04T00:00:00Z",
		EndFreshness:   "2026-08-04T00:01:00Z",
	}
	att.SelfDigest = attestation.ComputeSelfDigest(att)
	return att
}

// signPayload signs the canonical self-digest payload with priv and returns the signature bytes.
// The payload structure must match the one used by ComputeSelfDigest / verifySignature.
func signPayload(t *testing.T, att *attestation.AttestationV2, priv ed25519.PrivateKey) []byte {
	t.Helper()
	type payload struct {
		ProtocolVersion       int                              `json:"protocol_version"`
		ClaimID               string                           `json:"claim_id"`
		ClaimIdentityDigest   string                           `json:"claim_identity_digest"`
		CheckerIdentityDigest string                           `json:"checker_identity_digest"`
		RuntimeIdentityDigest string                           `json:"runtime_identity_digest"`
		EvidenceUsed          []string                         `json:"evidence_used"`
		ObligationResults     []attestation.ObligationResultV2 `json:"obligation_results"`
		Toolchain             map[string]string                `json:"toolchain,omitempty"`
		StartFreshness        string                           `json:"start_freshness"`
		EndFreshness          string                           `json:"end_freshness"`
	}
	p := payload{
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
		t.Fatalf("sign payload marshal: %v", err)
	}
	return ed25519.Sign(priv, data)
}

// pubkeyFingerprint returns sha256(raw_pubkey_bytes) as hex, matching the convention used
// by the attestation package.
func pubkeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return fmt.Sprintf("%x", sum)
}

// ── ComputeSelfDigest ─────────────────────────────────────────────────────────

func TestComputeSelfDigest_Format(t *testing.T) {
	t.Parallel()
	att := baseAttestation()
	d := attestation.ComputeSelfDigest(att)
	if len(d) != 7+64 {
		t.Errorf("expected sha256:<64hex> (len %d), got %q (len %d)", 7+64, d, len(d))
	}
}

func TestComputeSelfDigest_Deterministic(t *testing.T) {
	t.Parallel()
	att := baseAttestation()
	a := attestation.ComputeSelfDigest(att)
	b := attestation.ComputeSelfDigest(att)
	if a != b {
		t.Error("ComputeSelfDigest is not deterministic")
	}
}

func TestComputeSelfDigest_ExcludesSelfDigestAndSignature(t *testing.T) {
	t.Parallel()
	// Changing self_digest and signature must NOT change the hash output.
	att := baseAttestation()
	d1 := attestation.ComputeSelfDigest(att)

	att.SelfDigest = "garbage"
	att.Signature = &attestation.SignatureV2{Value: "noise"}
	d2 := attestation.ComputeSelfDigest(att)

	if d1 != d2 {
		t.Error("ComputeSelfDigest must not include self_digest or signature in its input")
	}
}

// ── Validate: happy path ──────────────────────────────────────────────────────

func TestValidate_Valid(t *testing.T) {
	t.Parallel()
	att := baseAttestation()
	if err := attestation.Validate(att, att.ClaimIdentityDigest, nil); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_EmptyCurrentIdentity_Skips(t *testing.T) {
	t.Parallel()
	att := baseAttestation()
	if err := attestation.Validate(att, "", nil); err != nil {
		t.Errorf("unexpected error with empty currentIdentity: %v", err)
	}
}

// ── Validate: reject paths ────────────────────────────────────────────────────

// INV-03: self_digest mismatch must be rejected.
func TestValidate_SelfDigestMismatch(t *testing.T) {
	t.Parallel()
	att := baseAttestation()
	att.SelfDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	err := attestation.Validate(att, att.ClaimIdentityDigest, nil)
	assertValidationCode(t, err, "SELF_DIGEST_MISMATCH", "INV-03")
}

// INV-02: claim_identity_digest mismatch → rejected.
func TestValidate_IdentityMismatch(t *testing.T) {
	t.Parallel()
	att := baseAttestation()
	err := attestation.Validate(att, "sha256:completely-different", nil)
	assertValidationCode(t, err, "IDENTITY_MISMATCH", "INV-02")
}

func TestValidate_WrongProtocolVersion(t *testing.T) {
	t.Parallel()
	att := baseAttestation()
	att.ProtocolVersion = 1
	att.SelfDigest = attestation.ComputeSelfDigest(att)
	err := attestation.Validate(att, att.ClaimIdentityDigest, nil)
	assertValidationCode(t, err, "PROTOCOL_VERSION", "protocol version check")
}

func TestValidate_EmptyObligations(t *testing.T) {
	t.Parallel()
	att := baseAttestation()
	att.ObligationResults = nil
	att.SelfDigest = attestation.ComputeSelfDigest(att)
	err := attestation.Validate(att, att.ClaimIdentityDigest, nil)
	assertValidationCode(t, err, "EMPTY_OBLIGATIONS", "INV-06 prerequisite")
}

// ── Validate: signature paths (INV-04) ───────────────────────────────────────

func TestValidate_SignatureValid(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	fp := pubkeyFingerprint(pub)
	att := baseAttestation()
	sigBytes := signPayload(t, att, priv)
	att.Signature = &attestation.SignatureV2{
		PubkeyFingerprint: fp,
		Algorithm:         "ed25519",
		Value:             base64.StdEncoding.EncodeToString(sigBytes),
	}
	att.SelfDigest = attestation.ComputeSelfDigest(att)

	trustedKeys := map[string]ed25519.PublicKey{fp: pub}
	if err := attestation.Validate(att, att.ClaimIdentityDigest, trustedKeys); err != nil {
		t.Errorf("unexpected error for valid signature (INV-04): %v", err)
	}
}

func TestValidate_SignatureUnknownKey(t *testing.T) {
	t.Parallel()
	att := baseAttestation()
	att.Signature = &attestation.SignatureV2{
		PubkeyFingerprint: "unknown-fp",
		Algorithm:         "ed25519",
		Value:             base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
	att.SelfDigest = attestation.ComputeSelfDigest(att)
	err := attestation.Validate(att, att.ClaimIdentityDigest, map[string]ed25519.PublicKey{})
	assertValidationCode(t, err, "UNKNOWN_KEY", "INV-04 unknown key")
}

func TestValidate_SignatureWrongAlgorithm(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	fp := pubkeyFingerprint(pub)
	att := baseAttestation()
	att.Signature = &attestation.SignatureV2{
		PubkeyFingerprint: fp,
		Algorithm:         "rsa",
		Value:             base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
	att.SelfDigest = attestation.ComputeSelfDigest(att)
	err := attestation.Validate(att, att.ClaimIdentityDigest, map[string]ed25519.PublicKey{fp: pub})
	assertValidationCode(t, err, "UNKNOWN_ALGORITHM", "unsupported algorithm")
}

func TestValidate_SignatureInvalidBase64(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	fp := pubkeyFingerprint(pub)
	att := baseAttestation()
	att.Signature = &attestation.SignatureV2{
		PubkeyFingerprint: fp,
		Algorithm:         "ed25519",
		Value:             "!!!not-base64!!!",
	}
	att.SelfDigest = attestation.ComputeSelfDigest(att)
	err := attestation.Validate(att, att.ClaimIdentityDigest, map[string]ed25519.PublicKey{fp: pub})
	assertValidationCode(t, err, "SIGNATURE_DECODE", "bad base64")
}

func TestValidate_SignatureWrongBytes(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	fp := pubkeyFingerprint(pub)
	att := baseAttestation()
	att.Signature = &attestation.SignatureV2{
		PubkeyFingerprint: fp,
		Algorithm:         "ed25519",
		Value:             base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
	att.SelfDigest = attestation.ComputeSelfDigest(att)
	err := attestation.Validate(att, att.ClaimIdentityDigest, map[string]ed25519.PublicKey{fp: pub})
	assertValidationCode(t, err, "SIGNATURE_INVALID", "INV-04 wrong sig bytes")
}

// ── helpers ───────────────────────────────────────────────────────────────────

func assertValidationCode(t *testing.T, err error, wantCode, context string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected ValidationError with code %q, got nil", context, wantCode)
	}
	ve, ok := err.(*attestation.ValidationError)
	if !ok {
		t.Fatalf("%s: expected *ValidationError, got %T: %v", context, err, err)
	}
	if ve.Code != wantCode {
		t.Errorf("%s: expected code %q, got %q (message: %s)", context, wantCode, ve.Code, ve.Message)
	}
}

func TestValidationError_Error(t *testing.T) {
	t.Parallel()
	ve := &attestation.ValidationError{Code: "TEST_CODE", Message: "something went wrong"}
	got := ve.Error()
	if got != "attestation [TEST_CODE]: something went wrong" {
		t.Errorf("unexpected error string: %q", got)
	}
}
