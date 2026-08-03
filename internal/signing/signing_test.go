package signing_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/telleroutlook/proofctl/internal/signing"
)

func TestGenerateKey_RoundTrip(t *testing.T) {
	t.Parallel()
	k, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if k.ID == "" {
		t.Error("key ID should not be empty")
	}
	if len(k.ID) != 16 {
		t.Errorf("fingerprint should be 16 hex chars, got %d: %q", len(k.ID), k.ID)
	}
	if k.PublicKey == nil {
		t.Error("public key should not be nil")
	}
	if k.PrivateKey == nil {
		t.Error("private key should not be nil")
	}
}

func TestSaveLoadPrivate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	k, _ := signing.GenerateKey()

	privPath := filepath.Join(dir, "key.priv")
	if err := k.SavePrivate(privPath); err != nil {
		t.Fatalf("SavePrivate: %v", err)
	}

	// Permissions must be 0600.
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("private key permissions: got %o, want 0600", info.Mode().Perm())
	}

	k2, err := signing.LoadPrivate(privPath)
	if err != nil {
		t.Fatalf("LoadPrivate: %v", err)
	}
	if k2.ID != k.ID {
		t.Errorf("fingerprint mismatch: got %q, want %q", k2.ID, k.ID)
	}
}

func TestSaveLoadPublic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	k, _ := signing.GenerateKey()

	pubPath := filepath.Join(dir, "key.pub")
	if err := k.SavePublic(pubPath); err != nil {
		t.Fatalf("SavePublic: %v", err)
	}

	k2, err := signing.LoadPublic(pubPath)
	if err != nil {
		t.Fatalf("LoadPublic: %v", err)
	}
	if k2.ID != k.ID {
		t.Errorf("fingerprint mismatch: got %q, want %q", k2.ID, k.ID)
	}
	if k2.PrivateKey != nil {
		t.Error("LoadPublic should not set PrivateKey")
	}
}

func TestSignVerify_Valid(t *testing.T) {
	t.Parallel()
	k, _ := signing.GenerateKey()

	payload := map[string]any{
		"claim_id": "thm-main",
		"outcome":  "accepted",
	}
	sig, err := k.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Algorithm != signing.Algorithm {
		t.Errorf("algorithm: got %q, want %q", sig.Algorithm, signing.Algorithm)
	}
	if sig.PubkeyFingerprint != k.ID {
		t.Errorf("fingerprint mismatch in signature")
	}

	pubKey := &signing.Key{ID: k.ID, PublicKey: k.PublicKey}
	if err := signing.Verify(pubKey, payload, sig); err != nil {
		t.Errorf("Verify valid signature: %v", err)
	}
}

func TestVerify_Tampered(t *testing.T) {
	t.Parallel()
	k, _ := signing.GenerateKey()
	payload := map[string]any{"claim_id": "x", "outcome": "accepted"}
	sig, _ := k.Sign(payload)

	// Tamper the payload.
	tampered := map[string]any{"claim_id": "x", "outcome": "rejected"}
	pubKey := &signing.Key{ID: k.ID, PublicKey: k.PublicKey}
	if err := signing.Verify(pubKey, tampered, sig); err == nil {
		t.Error("Verify tampered payload: expected error, got nil")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	t.Parallel()
	k1, _ := signing.GenerateKey()
	k2, _ := signing.GenerateKey()
	payload := map[string]any{"claim_id": "x"}
	sig, _ := k1.Sign(payload)

	wrongKey := &signing.Key{ID: k2.ID, PublicKey: k2.PublicKey}
	if err := signing.Verify(wrongKey, payload, sig); err == nil {
		t.Error("Verify with wrong key: expected error, got nil")
	}
}

func TestSign_RemovesSignatureField(t *testing.T) {
	t.Parallel()
	k, _ := signing.GenerateKey()
	// Payload already has a "signature" field — it should be stripped before signing.
	payload := map[string]any{
		"claim_id":  "x",
		"signature": map[string]any{"value": "old"},
	}
	sig1, err := k.Sign(payload)
	if err != nil {
		t.Fatalf("Sign with existing signature field: %v", err)
	}
	// Sign the same payload without the signature field — should produce same sig.
	payload2 := map[string]any{"claim_id": "x"}
	sig2, err := k.Sign(payload2)
	if err != nil {
		t.Fatalf("Sign without signature field: %v", err)
	}
	if sig1.Value != sig2.Value {
		t.Error("signature value differs when 'signature' field is present vs absent — stripping not working")
	}
}

func TestSign_NoPrivateKey(t *testing.T) {
	t.Parallel()
	k, _ := signing.GenerateKey()
	pubOnly := &signing.Key{ID: k.ID, PublicKey: k.PublicKey}
	_, err := pubOnly.Sign(map[string]any{"x": 1})
	if err == nil {
		t.Error("Sign with no private key: expected error, got nil")
	}
}

func TestSavePrivate_NoKey(t *testing.T) {
	t.Parallel()
	k := &signing.Key{}
	err := k.SavePrivate(filepath.Join(t.TempDir(), "key.priv"))
	if err == nil {
		t.Error("SavePrivate with nil PrivateKey: expected error, got nil")
	}
}

func TestLoadPrivate_InvalidFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.priv")
	if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}
	_, err := signing.LoadPrivate(path)
	if err == nil {
		t.Error("LoadPrivate invalid file: expected error, got nil")
	}
}
