package signing_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/telleroutlook/proofctl/internal/signing"
)

// TestSign_NoPrivateKey_PubOnly verifies that Sign returns an error when the key has
// no private component (loaded from a public key file only).
func TestSign_NoPrivateKey_PubOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	k, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubPath := filepath.Join(dir, "key.pub")
	if err := k.SavePublic(pubPath); err != nil {
		t.Fatalf("SavePublic: %v", err)
	}
	pubOnly, err := signing.LoadPublic(pubPath)
	if err != nil {
		t.Fatalf("LoadPublic: %v", err)
	}
	_, signErr := pubOnly.Sign(map[string]string{"claim_id": "test"})
	if signErr == nil {
		t.Fatal("expected error signing with public-only key, got nil")
	}
}

// TestLoadPublic_NotPEM verifies that LoadPublic returns an error for a file
// that contains no PEM block.
func TestLoadPublic_NotPEM(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pub")
	if err := os.WriteFile(path, []byte("not a pem file"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := signing.LoadPublic(path)
	if err == nil {
		t.Fatal("expected error for non-PEM public key file, got nil")
	}
}

// TestLoadPublic_WrongKeyType verifies that LoadPublic returns an error when
// the PEM block contains a private key rather than a public key.
func TestLoadPublic_WrongKeyType(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	k, _ := signing.GenerateKey()
	privPath := filepath.Join(dir, "key.priv")
	if err := k.SavePrivate(privPath); err != nil {
		t.Fatalf("SavePrivate: %v", err)
	}
	// LoadPublic on a private key file should fail (PKIX parse will fail on PKCS8 DER).
	_, err := signing.LoadPublic(privPath)
	if err == nil {
		t.Fatal("expected error loading private key file as public key, got nil")
	}
}

// TestLoadPrivate_NotPEM verifies that LoadPrivate returns an error for a file
// that contains no PEM block.
func TestLoadPrivate_NotPEM(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.priv")
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := signing.LoadPrivate(path)
	if err == nil {
		t.Fatal("expected error for non-PEM private key file, got nil")
	}
}

// TestVerify_WrongAlgorithm verifies that Verify returns an error for an
// unsupported algorithm identifier in the signature.
func TestVerify_WrongAlgorithm(t *testing.T) {
	t.Parallel()
	k, _ := signing.GenerateKey()
	sig := signing.Signature{
		PubkeyFingerprint: k.ID,
		Algorithm:         "rsa",
		Value:             "AAAA",
	}
	err := signing.Verify(k, map[string]string{"x": "1"}, sig)
	if err == nil {
		t.Fatal("expected error for unsupported algorithm, got nil")
	}
}

// TestVerify_BadBase64 verifies that Verify returns an error when the
// signature Value is not valid base64.
func TestVerify_BadBase64(t *testing.T) {
	t.Parallel()
	k, _ := signing.GenerateKey()
	sig := signing.Signature{
		PubkeyFingerprint: k.ID,
		Algorithm:         "ed25519",
		Value:             "!!!not-base64!!!",
	}
	err := signing.Verify(k, map[string]string{"x": "1"}, sig)
	if err == nil {
		t.Fatal("expected error for bad base64, got nil")
	}
}

// TestVerify_TamperedPayload verifies that Verify returns an error when the
// payload was modified after signing.
func TestVerify_TamperedPayload(t *testing.T) {
	t.Parallel()
	k, _ := signing.GenerateKey()
	payload := map[string]string{"claim_id": "original"}
	sig, err := k.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tampered := map[string]string{"claim_id": "tampered"}
	if verifyErr := signing.Verify(k, tampered, sig); verifyErr == nil {
		t.Fatal("expected error for tampered payload, got nil")
	}
}

// TestVerify_RoundTrip verifies that a valid sign+verify cycle succeeds.
func TestVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	k, _ := signing.GenerateKey()
	payload := map[string]string{"claim_id": "c1", "outcome": "accepted"}
	sig, err := k.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if verifyErr := signing.Verify(k, payload, sig); verifyErr != nil {
		t.Errorf("Verify: unexpected error: %v", verifyErr)
	}
}

// TestSign_NonObjectPayload verifies that signing a non-object value (array)
// works without error — canonicalForSigning falls back to signing as-is.
func TestSign_NonObjectPayload(t *testing.T) {
	t.Parallel()
	k, _ := signing.GenerateKey()
	sig, err := k.Sign([]string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("Sign of array: %v", err)
	}
	if err := signing.Verify(k, []string{"a", "b", "c"}, sig); err != nil {
		t.Errorf("Verify of array: %v", err)
	}
}

// TestSavePrivate_MissingDir verifies that SavePrivate returns an error when
// the parent directory does not exist.
func TestSavePrivate_MissingDir(t *testing.T) {
	t.Parallel()
	k, _ := signing.GenerateKey()
	err := k.SavePrivate("/nonexistent-dir/key.priv")
	if err == nil {
		t.Fatal("expected error for missing parent dir, got nil")
	}
}

// TestSavePublic_MissingDir verifies that SavePublic returns an error when
// the parent directory does not exist.
func TestSavePublic_MissingDir(t *testing.T) {
	t.Parallel()
	k, _ := signing.GenerateKey()
	err := k.SavePublic("/nonexistent-dir/key.pub")
	if err == nil {
		t.Fatal("expected error for missing parent dir, got nil")
	}
}
