// Package cas implements a content-addressed store for the ProofGraph Engine.
// Files are stored under <root>/<alg>/<first2>/<rest> and identified by their
// sha256 digest in the form "sha256:<hex>".
package cas

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// Store is a content-addressed blob store rooted at a directory.
type Store struct {
	root string
}

// New creates a Store rooted at the given directory.
// The directory is created if it does not exist.
func New(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("cas: create root: %w", err)
	}
	return &Store{root: root}, nil
}

// Store writes the content of r into the CAS and returns the digest and size.
// If a blob with the same digest already exists it is not overwritten.
func (s *Store) Store(r io.Reader) (digest string, size int64, err error) {
	// Write to a temp file while hashing.
	tmp, err := os.CreateTemp(s.root, "cas-tmp-*")
	if err != nil {
		return "", 0, fmt.Errorf("cas: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Clean up temp file on any error path.
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	h := sha256.New()
	w := io.MultiWriter(tmp, h)
	n, copyErr := io.Copy(w, r)
	if syncErr := tmp.Sync(); syncErr != nil && copyErr == nil {
		copyErr = syncErr
	}
	_ = tmp.Close()
	if copyErr != nil {
		return "", 0, fmt.Errorf("cas: write: %w", copyErr)
	}

	hexDigest := hex.EncodeToString(h.Sum(nil))
	digest = "sha256:" + hexDigest
	size = n

	blobPath := s.blobPath(hexDigest)
	if err2 := os.MkdirAll(filepath.Dir(blobPath), 0o755); err2 != nil {
		err = fmt.Errorf("cas: mkdir: %w", err2)
		return "", 0, err
	}

	// If the blob already exists, remove the temp file and return.
	if _, statErr := os.Stat(blobPath); statErr == nil {
		_ = os.Remove(tmpName)
		return digest, size, nil
	}

	if renameErr := os.Rename(tmpName, blobPath); renameErr != nil {
		err = fmt.Errorf("cas: finalize: %w", renameErr)
		return "", 0, err
	}
	return digest, size, nil
}

// Open returns a ReadCloser for the blob identified by digest.
func (s *Store) Open(digest string) (io.ReadCloser, error) {
	hexDigest, err := parseDigest(digest)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(s.blobPath(hexDigest))
	if err != nil {
		return nil, fmt.Errorf("cas: open %s: %w", digest, err)
	}
	return f, nil
}

// Verify checks that the stored blob matches the size and digest in desc.
// It must be called before parsing any evidence blob.
func (s *Store) Verify(desc ir.EvidenceDescriptor) error {
	hexDigest, err := parseDigest(desc.Digest)
	if err != nil {
		return err
	}

	f, err := os.Open(s.blobPath(hexDigest))
	if err != nil {
		return fmt.Errorf("cas: verify open %s: %w", desc.Digest, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("cas: verify stat: %w", err)
	}
	if info.Size() != desc.Size {
		return fmt.Errorf("cas: size mismatch for %s: want %d got %d",
			desc.Digest, desc.Size, info.Size())
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("cas: verify hash: %w", err)
	}
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if got != desc.Digest {
		return fmt.Errorf("cas: digest mismatch: want %s got %s", desc.Digest, got)
	}
	return nil
}

// blobPath returns the filesystem path for a hex digest.
func (s *Store) blobPath(hexDigest string) string {
	return filepath.Join(s.root, "sha256", hexDigest[:2], hexDigest[2:])
}

// parseDigest validates and strips the "sha256:" prefix from a digest string.
func parseDigest(digest string) (string, error) {
	hex, found := strings.CutPrefix(digest, "sha256:")
	if !found {
		return "", fmt.Errorf("cas: unsupported digest algorithm in %q", digest)
	}
	if len(hex) != 64 {
		return "", fmt.Errorf("cas: malformed sha256 digest %q", digest)
	}
	return hex, nil
}
