// Package freshness provides file-level freshness snapshots and drift detection.
// It is used to detect whether input files changed between the start and end of
// a checker invocation.
package freshness

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Snapshot returns a map from path to sha256 digest for each file in paths.
// Returns an error if any file cannot be read.
func Snapshot(paths []string) (map[string]string, error) {
	result := make(map[string]string, len(paths))
	for _, p := range paths {
		d, err := fileDigest(p)
		if err != nil {
			return nil, fmt.Errorf("freshness: snapshot %q: %w", p, err)
		}
		result[p] = d
	}
	return result, nil
}

// Verify checks that none of the paths in before have changed in after.
// It returns an error listing every path that changed, was added, or was removed.
func Verify(before, after map[string]string) error {
	var changed []string

	for path, beforeDigest := range before {
		afterDigest, exists := after[path]
		if !exists {
			changed = append(changed, fmt.Sprintf("%s: removed", path))
			continue
		}
		if beforeDigest != afterDigest {
			changed = append(changed, fmt.Sprintf("%s: digest changed", path))
		}
	}

	for path := range after {
		if _, exists := before[path]; !exists {
			changed = append(changed, fmt.Sprintf("%s: added", path))
		}
	}

	if len(changed) > 0 {
		msg := "freshness: inputs changed during checker invocation:\n"
		for _, c := range changed {
			msg += "  " + c + "\n"
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// fileDigest computes the sha256 digest of a file and returns it as "sha256:<hex>".
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
