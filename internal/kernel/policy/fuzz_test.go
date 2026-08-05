package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/telleroutlook/proofctl/internal/kernel/policy"
)

// FuzzLoadPolicyV2 fuzzes the strict JSON parser for PolicyV2File.
// Run with: go test -fuzz=FuzzLoadPolicyV2 -fuzztime=30s ./internal/kernel/policy/...
func FuzzLoadPolicyV2(f *testing.F) {
	// Seed corpus: valid and edge-case policy files.
	seeds := []string{
		`{"version":"2","target":"thm-main","allowed_assurances":["formal-kernel"]}`,
		`{"version":"2","target":"thm-main","forbidden_runtimes":["shadow","native-dev"]}`,
		`{"version":"2","target":"t","allowed_assurances":[],"required_claims":["a","b"]}`,
		`{"version":"1","target":"t"}`,
		`{}`,
		`{"version":"2"}`,
		`null`,
		`[]`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "policy.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Skip()
		}
		// LoadPolicyV2 must never panic — error is acceptable.
		_, _ = policy.LoadPolicyV2(path)
	})
}
