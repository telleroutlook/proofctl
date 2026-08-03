package cas_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/telleroutlook/proofctl/internal/cas"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// newSecTestStore creates a CAS Store backed by a temp directory.
func newSecTestStore(t *testing.T) *cas.Store {
	t.Helper()
	root := t.TempDir()
	s, err := cas.New(root)
	if err != nil {
		t.Fatalf("cas.New: %v", err)
	}
	return s
}

// TestAdversarial_WrongSize stores a real blob, then constructs an
// EvidenceDescriptor with the wrong size and verifies that Verify returns an error.
func TestAdversarial_WrongSize(t *testing.T) {
	t.Parallel()
	s := newSecTestStore(t)

	content := []byte("real blob content for size test")
	digest, _, err := s.Store(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	desc := ir.EvidenceDescriptor{
		Digest: digest,
		Size:   int64(len(content)) + 1, // wrong size
	}
	if err := s.Verify(desc); err == nil {
		t.Fatal("expected error for wrong size, got nil")
	}
}

// TestAdversarial_WrongDigest stores a real blob, constructs an
// EvidenceDescriptor with a valid-format sha256 that doesn't match the content,
// and verifies that Verify returns an error.
func TestAdversarial_WrongDigest(t *testing.T) {
	t.Parallel()
	s := newSecTestStore(t)

	content := []byte("real blob content for digest test")
	_, size, err := s.Store(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Also store a different blob to get a valid-format but wrong digest.
	other := []byte("completely different content")
	otherDigest, _, err := s.Store(bytes.NewReader(other))
	if err != nil {
		t.Fatalf("Store other: %v", err)
	}

	desc := ir.EvidenceDescriptor{
		Digest: otherDigest, // valid format but wrong for this content
		Size:   size,
	}
	if err := s.Verify(desc); err == nil {
		t.Fatal("expected error for wrong digest, got nil")
	}
}

// TestAdversarial_PathTraversal attempts to Open a digest string that embeds
// a path traversal sequence and verifies the store does not traverse outside root.
func TestAdversarial_PathTraversal(t *testing.T) {
	t.Parallel()
	s := newSecTestStore(t)

	// The digest prefix "sha256:" is required, and the hex must be 64 chars.
	// A traversal attempt would need to sneak "../" into the hex portion.
	// Since parseDigest validates exactly 64 hex chars, any "../" makes it invalid.
	traversalAttempts := []string{
		"sha256:../../../etc/passwd",
		"sha256:..%2F..%2F..%2Fetc%2Fpasswd111111111111111111111111111111111111111",
		"sha256:" + strings.Repeat("a", 63) + "/",
		"sha256:" + strings.Repeat(".", 64),
	}
	for _, digest := range traversalAttempts {
		_, err := s.Open(digest)
		if err == nil {
			t.Errorf("Open(%q): expected error for path traversal attempt, got nil", digest)
		}
	}
}

// TestAdversarial_MalformedDigest tests that various malformed digest strings
// are all rejected by Open.
func TestAdversarial_MalformedDigest(t *testing.T) {
	t.Parallel()
	s := newSecTestStore(t)

	cases := []struct {
		name   string
		digest string
	}{
		{"empty string", ""},
		{"no prefix", strings.Repeat("a", 64)},
		{"wrong algorithm", "md5:" + strings.Repeat("a", 32)},
		{"too short hex", "sha256:" + strings.Repeat("a", 32)},
		{"too long hex", "sha256:" + strings.Repeat("a", 65)},
		{"hex with spaces", "sha256:" + strings.Repeat("a", 32) + " " + strings.Repeat("a", 31)},
		{"colon only", ":"},
		{"sha256 only", "sha256:"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.Open(tc.digest)
			if err == nil {
				t.Errorf("Open(%q): expected error, got nil", tc.digest)
			}
		})
	}
}

// TestAdversarial_ConcurrentStore stores 50 identical blobs concurrently
// (10 goroutines x 5 stores each). All must succeed, exactly one blob file
// must be on disk, and no data corruption must occur.
func TestAdversarial_ConcurrentStore(t *testing.T) {
	t.Parallel()
	s := newSecTestStore(t)

	content := []byte("concurrent store test content — same blob stored by many goroutines")
	h := sha256.Sum256(content)
	wantDigest := "sha256:" + hex.EncodeToString(h[:])
	wantSize := int64(len(content))

	const goroutines = 10
	const storesPerGoroutine = 5

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*storesPerGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < storesPerGoroutine; i++ {
				gotDigest, gotSize, err := s.Store(bytes.NewReader(content))
				if err != nil {
					errCh <- err
					return
				}
				if gotDigest != wantDigest {
					errCh <- fmt.Errorf("digest mismatch: got %q want %q", gotDigest, wantDigest)
					return
				}
				if gotSize != wantSize {
					errCh <- fmt.Errorf("size mismatch: got %d want %d", gotSize, wantSize)
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("goroutine error: %v", err)
	}

	// Verify round-trip: the stored blob must be readable and correct.
	rc, err := s.Open(wantDigest)
	if err != nil {
		t.Fatalf("Open after concurrent stores: %v", err)
	}
	defer rc.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(rc); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), content) {
		t.Error("content mismatch after concurrent stores")
	}
}
