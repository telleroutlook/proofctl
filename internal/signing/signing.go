// Package signing provides Ed25519 key generation, signing, and verification
// for proofctl attestations.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

// Algorithm is the signing algorithm identifier embedded in attestation signatures.
const Algorithm = "ed25519"

// Key holds an Ed25519 key pair. PrivateKey may be nil for verify-only use.
type Key struct {
	ID         string // fingerprint: first 16 hex chars of sha256(pubkey)
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey // nil if loaded from public key only
}

// Signature is the JSON-serialisable signature attached to an attestation.
type Signature struct {
	PubkeyFingerprint string `json:"pubkey_fingerprint"`
	Algorithm         string `json:"algorithm"`
	Value             string `json:"value"` // base64-encoded signature bytes
}

// GenerateKey creates a new Ed25519 key pair.
func GenerateKey() (*Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signing: generate key: %w", err)
	}
	return &Key{
		ID:         fingerprint(pub),
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// SavePrivate writes the private key to path with mode 0600 (PEM PKCS8).
func (k *Key) SavePrivate(path string) error {
	if k.PrivateKey == nil {
		return fmt.Errorf("signing: no private key to save")
	}
	der, err := x509.MarshalPKCS8PrivateKey(k.PrivateKey)
	if err != nil {
		return fmt.Errorf("signing: marshal private key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("signing: create private key file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return pem.Encode(f, block)
}

// SavePublic writes the public key to path with mode 0644 (PEM PKIX).
func (k *Key) SavePublic(path string) error {
	der, err := x509.MarshalPKIXPublicKey(k.PublicKey)
	if err != nil {
		return fmt.Errorf("signing: marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("signing: create public key file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return pem.Encode(f, block)
}

// LoadPrivate reads a PEM PKCS8 private key from path.
func LoadPrivate(path string) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signing: read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signing: no PEM block in %s", path)
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing: parse private key: %w", err)
	}
	priv, ok := raw.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing: %s is not an Ed25519 private key", path)
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &Key{
		ID:         fingerprint(pub),
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// LoadPublic reads a PEM PKIX public key from path.
func LoadPublic(path string) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signing: read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signing: no PEM block in %s", path)
	}
	raw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing: parse public key: %w", err)
	}
	pub, ok := raw.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signing: %s is not an Ed25519 public key", path)
	}
	return &Key{
		ID:        fingerprint(pub),
		PublicKey: pub,
	}, nil
}

// Sign signs the canonical JSON representation of v (with the "signature" field
// removed) and returns a Signature.
func (k *Key) Sign(v any) (Signature, error) {
	if k.PrivateKey == nil {
		return Signature{}, fmt.Errorf("signing: no private key loaded")
	}
	msg, err := canonicalForSigning(v)
	if err != nil {
		return Signature{}, err
	}
	sig := ed25519.Sign(k.PrivateKey, msg)
	return Signature{
		PubkeyFingerprint: k.ID,
		Algorithm:         Algorithm,
		Value:             base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify checks sig against the canonical JSON of v (signature field removed).
// Returns nil if valid.
func Verify(pub *Key, v any, sig Signature) error {
	if sig.Algorithm != Algorithm {
		return fmt.Errorf("signing: unsupported algorithm %q", sig.Algorithm)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("signing: decode signature value: %w", err)
	}
	msg, err := canonicalForSigning(v)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub.PublicKey, msg, sigBytes) {
		return fmt.Errorf("signing: signature verification failed")
	}
	return nil
}

// SignBytes signs raw bytes directly (no JSON marshalling).
func (k *Key) SignBytes(data []byte) (Signature, error) {
	if k.PrivateKey == nil {
		return Signature{}, fmt.Errorf("signing: no private key loaded")
	}
	sig := ed25519.Sign(k.PrivateKey, data)
	return Signature{
		PubkeyFingerprint: k.ID,
		Algorithm:         Algorithm,
		Value:             base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyBytes verifies sig against raw bytes directly.
func VerifyBytes(pub *Key, data []byte, sig Signature) error {
	if sig.Algorithm != Algorithm {
		return fmt.Errorf("signing: unsupported algorithm %q", sig.Algorithm)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("signing: decode signature value: %w", err)
	}
	if !ed25519.Verify(pub.PublicKey, data, sigBytes) {
		return fmt.Errorf("signing: signature verification failed")
	}
	return nil
}

// canonicalForSigning marshals v to JSON, removes the "signature" key if
// present, then re-marshals for signing/verification.
func canonicalForSigning(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("signing: marshal for signing: %w", err)
	}
	// Remove "signature" field so sign and verify operate on the same payload.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		// Not an object (e.g. array/scalar) — sign as-is.
		return data, nil
	}
	delete(m, "signature")
	canonical, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("signing: re-marshal for signing: %w", err)
	}
	return canonical, nil
}

// fingerprint returns the first 16 hex characters of sha256(pubkey bytes).
func fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return fmt.Sprintf("%x", sum[:8]) // 8 bytes = 16 hex chars
}
