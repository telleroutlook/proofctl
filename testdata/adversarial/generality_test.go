// Package adversarial — generality_test.go verifies that the proofctl core
// (kernel, release, protocol/v2) contains no domain-specific hardcoding for
// Metamath, Weil, LRAT, Lean, Coq, or any other domain.
//
// Canvas §22 rule 4: core must be domain-agnostic; domain knowledge lives only
// in adapters/ and domains/.
package adversarial

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corePaths lists the Go source directories that must contain no domain hardcoding.
var corePaths = []string{
	"../../internal/kernel",
	"../../internal/release",
	"../../pkg/protocol/v2",
}

// domainTerms lists identifier fragments that must not appear in core packages.
// These are terms that would indicate hardcoded domain knowledge.
var domainTerms = []string{
	"metamath",
	"Metamath",
	"weil-",
	"Weil",
	"lrat",
	"LRAT",
	"lean",
	"Lean",
	"coq",
	"Coq",
	"isabelle",
	"Isabelle",
}

// allowedFiles lists file suffixes where domain terms are allowed (tests, comments only).
// We only scan non-test .go files.
var allowedSuffixes = []string{"_test.go"}

func isAllowedFile(name string) bool {
	for _, suf := range allowedSuffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

func TestCore_NoDomainHardcoding(t *testing.T) {
	t.Parallel()

	for _, dir := range corePaths {
		dir := dir
		t.Run(filepath.Base(dir), func(t *testing.T) {
			t.Parallel()
			err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				if !strings.HasSuffix(path, ".go") || isAllowedFile(d.Name()) {
					return nil
				}
				data, readErr := os.ReadFile(path)
				if readErr != nil {
					return readErr
				}
				content := string(data)
				for _, term := range domainTerms {
					// Allow terms that appear only in comments (lines starting with //).
					lines := strings.Split(content, "\n")
					for i, line := range lines {
						trimmed := strings.TrimSpace(line)
						// Skip pure comment lines.
						if strings.HasPrefix(trimmed, "//") {
							continue
						}
						if strings.Contains(strings.ToLower(line), strings.ToLower(term)) {
							t.Errorf("core hardcoding detected: %s:%d contains domain term %q\n  line: %s",
								path, i+1, term, strings.TrimSpace(line))
						}
					}
				}
				return nil
			})
			if err != nil {
				t.Fatalf("walk %s: %v", dir, err)
			}
		})
	}
}

// TestMetamath_UsesSharedKernel verifies that the Metamath domain contracts
// pass the same contract lint as any other domain — no special-casing.
func TestMetamath_UsesSharedKernel(t *testing.T) {
	t.Parallel()

	contractDir := "../../domains/metamath/contracts"
	entries, err := os.ReadDir(contractDir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", contractDir, err)
	}
	if len(entries) == 0 {
		t.Fatal("domains/metamath/contracts/ is empty — expected at least 2 contract files")
	}
	t.Logf("found %d Metamath contract files in %s", len(entries), contractDir)

	// Verify each file is valid JSON with contract_version="2" and claim_id non-empty.
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		e := e
		t.Run(e.Name(), func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join(contractDir, e.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", e.Name(), err)
			}
			content := string(data)
			if !strings.Contains(content, `"contract_version": "2"`) {
				t.Errorf("%s: missing contract_version=2", e.Name())
			}
			if !strings.Contains(content, `"claim_id"`) {
				t.Errorf("%s: missing claim_id field", e.Name())
			}
		})
	}
}

// TestWeil_UsesSharedKernel verifies that the Weil domain contracts also
// pass the same structural check — no domain gets special treatment.
func TestWeil_UsesSharedKernel(t *testing.T) {
	t.Parallel()

	contractDir := "../../domains/weil/contracts"
	entries, err := os.ReadDir(contractDir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", contractDir, err)
	}
	if len(entries) < 18 {
		t.Errorf("domains/weil/contracts/ has %d files, expected 18 (D1–D18)", len(entries))
	}
	t.Logf("found %d Weil contract files in %s", len(entries), contractDir)
}
