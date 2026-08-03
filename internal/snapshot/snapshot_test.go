package snapshot_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
	"github.com/telleroutlook/proofctl/internal/snapshot"
)

const testTime = "2026-08-03T00:00:00Z"

func makeClaims(ids ...string) []ir.Claim {
	claims := make([]ir.Claim, len(ids))
	for i, id := range ids {
		claims[i] = ir.Claim{ID: id, Kind: "lemma"}
	}
	return claims
}

func makeAttestations(ids ...string) map[string]*ir.Attestation {
	m := make(map[string]*ir.Attestation, len(ids))
	for _, id := range ids {
		m[id] = &ir.Attestation{
			ClaimID:   id,
			Outcome:   "accepted",
			Assurance: ir.AssuranceFormalKernel,
		}
	}
	return m
}

// TestTake_Deterministic verifies that identical inputs always produce the same SelfDigest.
func TestTake_Deterministic(t *testing.T) {
	claims := makeClaims("c1", "c2")
	atts := makeAttestations("c1", "c2")
	statuses := map[string]ir.Status{"c1": ir.StatusAccepted, "c2": ir.StatusAccepted}

	s1, err := snapshot.Take(claims, atts, statuses, testTime)
	if err != nil {
		t.Fatalf("Take #1 failed: %v", err)
	}
	s2, err := snapshot.Take(claims, atts, statuses, testTime)
	if err != nil {
		t.Fatalf("Take #2 failed: %v", err)
	}
	if s1.SelfDigest != s2.SelfDigest {
		t.Errorf("same inputs produced different digests:\n  %s\n  %s", s1.SelfDigest, s2.SelfDigest)
	}
}

// TestTake_DifferentClaim verifies that a changed claim produces a different SelfDigest.
func TestTake_DifferentClaim(t *testing.T) {
	claimsA := makeClaims("c1", "c2")
	claimsB := makeClaims("c1", "c3") // c2 replaced with c3
	atts := makeAttestations("c1", "c2")
	statuses := map[string]ir.Status{"c1": ir.StatusAccepted, "c2": ir.StatusAccepted}

	s1, err := snapshot.Take(claimsA, atts, statuses, testTime)
	if err != nil {
		t.Fatalf("Take A failed: %v", err)
	}
	s2, err := snapshot.Take(claimsB, atts, statuses, testTime)
	if err != nil {
		t.Fatalf("Take B failed: %v", err)
	}
	if s1.SelfDigest == s2.SelfDigest {
		t.Error("different claims should produce different digests")
	}
}

// TestTake_DifferentAttestation verifies that a changed attestation produces a different SelfDigest.
func TestTake_DifferentAttestation(t *testing.T) {
	claims := makeClaims("c1")
	statuses := map[string]ir.Status{"c1": ir.StatusAccepted}

	attsA := map[string]*ir.Attestation{
		"c1": {ClaimID: "c1", Outcome: "accepted", Assurance: ir.AssuranceFormalKernel},
	}
	attsB := map[string]*ir.Attestation{
		"c1": {ClaimID: "c1", Outcome: "rejected", Assurance: ir.AssuranceFormalKernel},
	}

	s1, err := snapshot.Take(claims, attsA, statuses, testTime)
	if err != nil {
		t.Fatalf("Take A failed: %v", err)
	}
	s2, err := snapshot.Take(claims, attsB, statuses, testTime)
	if err != nil {
		t.Fatalf("Take B failed: %v", err)
	}
	if s1.SelfDigest == s2.SelfDigest {
		t.Error("different attestations should produce different digests")
	}
}

// TestTake_SortedClaims verifies that claims are always sorted by ID in the snapshot,
// regardless of input order.
func TestTake_SortedClaims(t *testing.T) {
	// Provide claims in reverse alphabetical order.
	claims := makeClaims("z-claim", "m-claim", "a-claim")
	atts := makeAttestations("z-claim", "m-claim", "a-claim")
	statuses := map[string]ir.Status{
		"z-claim": ir.StatusAccepted,
		"m-claim": ir.StatusAccepted,
		"a-claim": ir.StatusAccepted,
	}

	snap, err := snapshot.Take(claims, atts, statuses, testTime)
	if err != nil {
		t.Fatalf("Take failed: %v", err)
	}
	if len(snap.Claims) != 3 {
		t.Fatalf("expected 3 claims, got %d", len(snap.Claims))
	}
	if snap.Claims[0].ID != "a-claim" || snap.Claims[1].ID != "m-claim" || snap.Claims[2].ID != "z-claim" {
		t.Errorf("claims not sorted: got %q %q %q",
			snap.Claims[0].ID, snap.Claims[1].ID, snap.Claims[2].ID)
	}
}

// TestWrite_CreatesFile verifies that Write creates a valid JSON file in the target directory.
func TestWrite_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	claims := makeClaims("c1")
	atts := makeAttestations("c1")
	statuses := map[string]ir.Status{"c1": ir.StatusAccepted}

	snap, err := snapshot.Take(claims, atts, statuses, testTime)
	if err != nil {
		t.Fatalf("Take failed: %v", err)
	}

	path, err := snapshot.Write(snap, dir)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// File must exist.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not found at %s: %v", path, err)
	}

	// File must be valid JSON that round-trips back to a Snapshot.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file failed: %v", err)
	}
	var got snapshot.Snapshot
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.SelfDigest != snap.SelfDigest {
		t.Errorf("SelfDigest mismatch: %q != %q", got.SelfDigest, snap.SelfDigest)
	}

	// Filename must contain the first 16 hex chars of the digest.
	base := filepath.Base(path)
	digestHex := snap.SelfDigest[7:23] // strip "sha256:" take first 16
	if base != digestHex+".snapshot.json" {
		t.Errorf("unexpected filename %q, expected %q", base, digestHex+".snapshot.json")
	}
}

// TestWrite_Idempotent verifies that writing the same snapshot twice produces the same filename.
func TestWrite_Idempotent(t *testing.T) {
	dir := t.TempDir()
	claims := makeClaims("c1", "c2")
	atts := makeAttestations("c1", "c2")
	statuses := map[string]ir.Status{"c1": ir.StatusAccepted, "c2": ir.StatusAccepted}

	snap, err := snapshot.Take(claims, atts, statuses, testTime)
	if err != nil {
		t.Fatalf("Take failed: %v", err)
	}

	path1, err := snapshot.Write(snap, dir)
	if err != nil {
		t.Fatalf("Write #1 failed: %v", err)
	}
	path2, err := snapshot.Write(snap, dir)
	if err != nil {
		t.Fatalf("Write #2 failed: %v", err)
	}

	if path1 != path2 {
		t.Errorf("second write produced different path:\n  first:  %s\n  second: %s", path1, path2)
	}

	// Only one file should exist in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 file in dir after 2 writes of same snapshot, got %d", count)
	}
}
