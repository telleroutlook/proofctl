package cas

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// TestStoreSmallBlob checks that storing a small blob returns the correct sha256 digest and size.
func TestStoreSmallBlob(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	content := []byte("hello world")
	wantHex := sha256hex(content)
	wantDigest := "sha256:" + wantHex
	wantSize := int64(len(content))

	gotDigest, gotSize, err := s.Store(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if gotDigest != wantDigest {
		t.Errorf("digest: got %q want %q", gotDigest, wantDigest)
	}
	if gotSize != wantSize {
		t.Errorf("size: got %d want %d", gotSize, wantSize)
	}
}

// TestStoreIdempotent checks that storing the same blob twice is idempotent.
func TestStoreIdempotent(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	content := []byte("idempotent content")
	d1, sz1, err := s.Store(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("first Store: %v", err)
	}
	d2, sz2, err := s.Store(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("second Store: %v", err)
	}
	if d1 != d2 {
		t.Errorf("digest changed between stores: %q vs %q", d1, d2)
	}
	if sz1 != sz2 {
		t.Errorf("size changed between stores: %d vs %d", sz1, sz2)
	}
}

// TestOpenExistingBlob checks that Open returns the original bytes.
func TestOpenExistingBlob(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	content := []byte("round-trip content")
	digest, _, err := s.Store(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	rc, err := s.Open(digest)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch: got %q want %q", got, content)
	}
}

// TestOpenNonexistent checks that opening a nonexistent digest returns an error.
func TestOpenNonexistent(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	fakeDigest := "sha256:" + strings.Repeat("a", 64)
	_, err := s.Open(fakeDigest)
	if err == nil {
		t.Fatal("expected error for nonexistent digest, got nil")
	}
}

// TestVerifyCorrectDescriptor checks that Verify returns nil for a correct descriptor.
func TestVerifyCorrectDescriptor(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	content := []byte("verify me")
	digest, size, err := s.Store(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	desc := ir.EvidenceDescriptor{
		Digest: digest,
		Size:   size,
	}
	if err := s.Verify(desc); err != nil {
		t.Errorf("Verify: unexpected error: %v", err)
	}
}

// TestVerifyWrongSize checks that Verify returns an error when the size is wrong.
func TestVerifyWrongSize(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	content := []byte("size check content")
	digest, size, err := s.Store(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	desc := ir.EvidenceDescriptor{
		Digest: digest,
		Size:   size + 99,
	}
	if err := s.Verify(desc); err == nil {
		t.Fatal("expected error for wrong size, got nil")
	}
}

// TestVerifyWrongDigest checks that Verify returns an error when the digest does not match.
func TestVerifyWrongDigest(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	content := []byte("digest mismatch content")
	_, size, err := s.Store(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Store a different blob and use its digest for the wrong descriptor.
	other := []byte("completely different blob for mismatch test")
	otherDigest, _, err := s.Store(bytes.NewReader(other))
	if err != nil {
		t.Fatalf("Store other: %v", err)
	}

	desc := ir.EvidenceDescriptor{
		Digest: otherDigest,
		Size:   size, // size of first blob but digest of second
	}
	if err := s.Verify(desc); err == nil {
		t.Fatal("expected error for digest/size mismatch, got nil")
	}
}

// TestStoreEmptyBlob checks that storing an empty blob produces the correct sha256 digest.
func TestStoreEmptyBlob(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	wantHex := sha256hex([]byte{})
	wantDigest := "sha256:" + wantHex

	gotDigest, gotSize, err := s.Store(bytes.NewReader([]byte{}))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if gotDigest != wantDigest {
		t.Errorf("empty blob digest: got %q want %q", gotDigest, wantDigest)
	}
	if gotSize != 0 {
		t.Errorf("empty blob size: got %d want 0", gotSize)
	}

	// Should also be openable.
	rc, err := s.Open(gotDigest)
	if err != nil {
		t.Fatalf("Open empty blob: %v", err)
	}
	rc.Close()
}

// TestParseDigestMissingPrefix checks that parseDigest rejects a string without the sha256: prefix.
func TestParseDigestMissingPrefix(t *testing.T) {
	t.Parallel()
	_, err := parseDigest(strings.Repeat("a", 64))
	if err == nil {
		t.Fatal("expected error for missing prefix, got nil")
	}
}

// TestParseDigestWrongLengthHex checks that parseDigest rejects a sha256: prefixed string with wrong hex length.
func TestParseDigestWrongLengthHex(t *testing.T) {
	t.Parallel()
	// 32 hex chars instead of 64.
	_, err := parseDigest("sha256:" + strings.Repeat("a", 32))
	if err == nil {
		t.Fatal("expected error for wrong-length hex, got nil")
	}
}

// TestParseDigestValid checks that parseDigest accepts a valid sha256 digest.
func TestParseDigestValid(t *testing.T) {
	t.Parallel()
	hexStr := strings.Repeat("a", 64)
	got, err := parseDigest("sha256:" + hexStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != hexStr {
		t.Errorf("got %q want %q", got, hexStr)
	}
}

// TestOpenInvalidDigestFormat checks that Open with malformed digest returns an error.
func TestOpenInvalidDigestFormat(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	_, err := s.Open("notadigest")
	if err == nil {
		t.Fatal("expected error for invalid digest format, got nil")
	}
}

// newTestStore creates a CAS Store backed by a temp directory.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("cas.New: %v", err)
	}
	return s
}

// sha256hex computes the sha256 hex string of data.
func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
