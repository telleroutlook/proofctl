// Package snapshot produces an immutable, content-addressed ProofGraph snapshot.
// A snapshot captures the full graph + all attestations at a point in time.
// It is written atomically; once written it is never modified.
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// Snapshot is an immutable record of graph + attestation state.
type Snapshot struct {
	Version      string                     `json:"version"`
	CreatedAt    string                     `json:"created_at"` // RFC3339
	GraphDigest  string                     `json:"graph_digest"`
	Claims       []ir.Claim                 `json:"claims"`
	Attestations map[string]*ir.Attestation `json:"attestations"`
	Statuses     map[string]string          `json:"statuses"`
	SelfDigest   string                     `json:"self_digest"`
}

// Take creates a snapshot from the current graph and attestation state.
// createdAt is passed in (not derived from time.Now()) so snapshots are deterministic.
func Take(
	claims []ir.Claim,
	attestations map[string]*ir.Attestation,
	statuses map[string]ir.Status,
	createdAt string,
) (*Snapshot, error) {
	// Build sorted claims list for determinism.
	sorted := make([]ir.Claim, len(claims))
	copy(sorted, claims)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	// Build status map as strings.
	statusStrs := make(map[string]string, len(statuses))
	for id, s := range statuses {
		statusStrs[id] = string(s)
	}

	// Compute graph digest.
	graphData, err := json.Marshal(sorted)
	if err != nil {
		return nil, fmt.Errorf("snapshot: marshal claims: %w", err)
	}
	gsum := sha256.Sum256(graphData)
	graphDigest := "sha256:" + hex.EncodeToString(gsum[:])

	snap := &Snapshot{
		Version:      "1",
		CreatedAt:    createdAt,
		GraphDigest:  graphDigest,
		Claims:       sorted,
		Attestations: attestations,
		Statuses:     statusStrs,
	}

	// Compute self-digest (with SelfDigest zeroed).
	snap.SelfDigest = ""
	data, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("snapshot: marshal for digest: %w", err)
	}
	sum := sha256.Sum256(data)
	snap.SelfDigest = "sha256:" + hex.EncodeToString(sum[:])

	return snap, nil
}

// Write atomically writes the snapshot to dir/<self_digest[:16]>.snapshot.json.
// Returns the path written.
func Write(snap *Snapshot, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("snapshot: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return "", fmt.Errorf("snapshot: marshal: %w", err)
	}
	data = append(data, '\n')

	// Strip "sha256:" prefix and take first 16 hex chars as filename.
	name := snap.SelfDigest[7:23] + ".snapshot.json"
	target := filepath.Join(dir, name)

	tmp, err := os.CreateTemp(dir, "snap-tmp-*")
	if err != nil {
		return "", fmt.Errorf("snapshot: create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("snapshot: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("snapshot: sync: %w", err)
	}
	_ = tmp.Close()
	if err := os.Rename(tmpName, target); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("snapshot: rename: %w", err)
	}
	return target, nil
}
