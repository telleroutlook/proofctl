package freshness

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestSnapshotExistingFile checks that Snapshot of an existing file returns a sha256 entry.
func TestSnapshotExistingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	snap, err := Snapshot([]string{path})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	digest, ok := snap[path]
	if !ok {
		t.Fatalf("expected entry for %q in snapshot", path)
	}
	if len(digest) == 0 {
		t.Error("expected non-empty digest")
	}
	// Digest must have sha256: prefix.
	if len(digest) < 7 || digest[:7] != "sha256:" {
		t.Errorf("expected sha256: prefix in digest, got %q", digest)
	}
}

// TestSnapshotNonexistentFile checks that Snapshot of a nonexistent file returns an error.
func TestSnapshotNonexistentFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.txt")

	_, err := Snapshot([]string{path})
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

// TestVerifyIdenticalSnapshots checks that Verify returns nil when snapshots are identical.
func TestVerifyIdenticalSnapshots(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "same.txt")
	if err := os.WriteFile(path, []byte("content"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	before, err := Snapshot([]string{path})
	if err != nil {
		t.Fatalf("Snapshot before: %v", err)
	}
	after, err := Snapshot([]string{path})
	if err != nil {
		t.Fatalf("Snapshot after: %v", err)
	}

	if err := Verify(before, after); err != nil {
		t.Errorf("expected nil for identical snapshots, got: %v", err)
	}
}

// TestVerifyModifiedFile checks that Verify returns an error when a file is modified.
func TestVerifyModifiedFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "modified.txt")
	if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	before, err := Snapshot([]string{path})
	if err != nil {
		t.Fatalf("Snapshot before: %v", err)
	}

	// Modify the file.
	if err := os.WriteFile(path, []byte("modified content"), 0o644); err != nil {
		t.Fatalf("WriteFile modify: %v", err)
	}

	after, err := Snapshot([]string{path})
	if err != nil {
		t.Fatalf("Snapshot after: %v", err)
	}

	if err := Verify(before, after); err == nil {
		t.Fatal("expected error for modified file, got nil")
	}
}

// TestVerifyDeletedFile checks that Verify returns an error when a file is deleted from after.
func TestVerifyDeletedFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "deleted.txt")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	before, err := Snapshot([]string{path})
	if err != nil {
		t.Fatalf("Snapshot before: %v", err)
	}

	// Simulate deletion by creating an after map without the path.
	after := map[string]string{}

	if err := Verify(before, after); err == nil {
		t.Fatal("expected error for deleted file, got nil")
	}
}

// TestVerifyEmptyMaps checks that Verify with two empty maps returns nil.
func TestVerifyEmptyMaps(t *testing.T) {
	t.Parallel()
	before := map[string]string{}
	after := map[string]string{}
	if err := Verify(before, after); err != nil {
		t.Errorf("expected nil for empty maps, got: %v", err)
	}
}

// TestVerifyAddedFile checks that Verify returns an error when a new file appears in after.
func TestVerifyAddedFile(t *testing.T) {
	t.Parallel()
	before := map[string]string{}
	after := map[string]string{
		"/some/new/file.txt": "sha256:" + "a" + repeat('a', 63),
	}
	if err := Verify(before, after); err == nil {
		t.Fatal("expected error for added file, got nil")
	}
}

// TestSnapshotMultipleFiles checks that Snapshot handles multiple files correctly.
func TestSnapshotMultipleFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "a.txt"),
		filepath.Join(dir, "b.txt"),
		filepath.Join(dir, "c.txt"),
	}
	for i, p := range paths {
		content := []byte{'A' + byte(i)}
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", p, err)
		}
	}

	snap, err := Snapshot(paths)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap) != len(paths) {
		t.Errorf("expected %d entries, got %d", len(paths), len(snap))
	}
	for _, p := range paths {
		if _, ok := snap[p]; !ok {
			t.Errorf("missing entry for %q", p)
		}
	}
}

// TestAdversarial_SymlinkTarget checks that Snapshot hashes the content of a
// symlink target, not just the link itself, so that replacing the target is
// detected as a freshness violation.
func TestAdversarial_SymlinkTarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create the real target file.
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Create a symlink pointing at the target.
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks not supported on this filesystem: %v", err)
	}

	// Take before snapshot through the symlink.
	before, err := Snapshot([]string{link})
	if err != nil {
		t.Fatalf("Snapshot before: %v", err)
	}

	// Replace the symlink target content.
	if err := os.WriteFile(target, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("WriteFile tamper: %v", err)
	}

	// Take after snapshot through the same symlink.
	after, err := Snapshot([]string{link})
	if err != nil {
		t.Fatalf("Snapshot after: %v", err)
	}

	// Verify must detect the content change.
	if err := Verify(before, after); err == nil {
		t.Fatal("expected freshness violation when symlink target content changes, got nil")
	}
}

// TestAdversarial_SymlinkRetarget checks that redirecting a symlink to a
// different file (while keeping the link path constant) is detected.
func TestAdversarial_SymlinkRetarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	original := filepath.Join(dir, "original.txt")
	replacement := filepath.Join(dir, "replacement.txt")
	if err := os.WriteFile(original, []byte("original content"), 0o644); err != nil {
		t.Fatalf("WriteFile original: %v", err)
	}
	if err := os.WriteFile(replacement, []byte("replacement content"), 0o644); err != nil {
		t.Fatalf("WriteFile replacement: %v", err)
	}

	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(original, link); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	before, err := Snapshot([]string{link})
	if err != nil {
		t.Fatalf("Snapshot before: %v", err)
	}

	// Atomically retarget the symlink (remove + re-create).
	if err := os.Remove(link); err != nil {
		t.Fatalf("Remove link: %v", err)
	}
	if err := os.Symlink(replacement, link); err != nil {
		t.Fatalf("Symlink retarget: %v", err)
	}

	after, err := Snapshot([]string{link})
	if err != nil {
		t.Fatalf("Snapshot after: %v", err)
	}

	if err := Verify(before, after); err == nil {
		t.Fatal("expected freshness violation when symlink is retargeted, got nil")
	}
}

// TestAdversarial_ConcurrentModification performs a real goroutine TOCTOU
// race: one goroutine repeatedly rewrites a file while the main goroutine
// takes before/after snapshots and checks for violations. The test asserts
// that at least one snapshot pair detects a change — i.e. the freshness check
// is not blind to concurrent mutations.
func TestAdversarial_ConcurrentModification(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.txt")

	if err := os.WriteFile(path, []byte("version-0"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Background writer: keeps flipping the file content.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.WriteFile(path, []byte(fmt.Sprintf("version-%d", i)), 0o644)
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()

	// Sample up to 200 snapshot pairs; expect at least one to catch a change.
	caught := false
	for attempt := 0; attempt < 200; attempt++ {
		before, err := Snapshot([]string{path})
		if err != nil {
			continue // file may be mid-write; skip this sample
		}
		after, err := Snapshot([]string{path})
		if err != nil {
			continue
		}
		if Verify(before, after) != nil {
			caught = true
			break
		}
	}

	if !caught {
		t.Error("freshness check never detected concurrent file modification in 200 attempts")
	}
}

// repeat returns a string of n copies of the byte b as a rune.
func repeat(b rune, n int) string {
	s := make([]rune, n)
	for i := range s {
		s[i] = b
	}
	return string(s)
}
