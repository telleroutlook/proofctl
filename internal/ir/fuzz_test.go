//go:build go1.18

package ir_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// FuzzDecodeStrict_Claim fuzzes the Claim decoder. It must never panic.
// Errors are acceptable; panics are not.
func FuzzDecodeStrict_Claim(f *testing.F) {
	// Seed corpus: valid claim, unknown field, duplicate key, truncated, empty.
	f.Add([]byte(`{"id":"x","kind":"definition","statement":{"text":"t","digest":"sha256:abc"},"depends_on":[],"required_assurance":[],"evidence":[],"checker_policy":""}`))
	f.Add([]byte(`{"id":"x","id":"y"}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"id":"x","injected":"bad"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic. Error is fine; panic is not.
		_, _ = ir.DecodeStrict[ir.Claim](bytes.NewReader(data))
	})
}

// FuzzCanonicalJSON fuzzes the CanonicalJSON function.
// The key invariant: if it succeeds, applying it a second time must yield the same result.
func FuzzCanonicalJSON(f *testing.F) {
	f.Add([]byte(`{"b":1,"a":2}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"a":{"c":3,"b":2}}`))
	f.Add([]byte(`"hello"`))
	f.Add([]byte(`42`))
	f.Add([]byte(`true`))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Unmarshal first to any, then call CanonicalJSON.
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			// Invalid JSON — skip.
			return
		}

		result, err := ir.CanonicalJSON(v)
		if err != nil {
			// Errors from CanonicalJSON are acceptable.
			return
		}

		// Idempotency: unmarshal the result and re-canonicalize.
		var v2 any
		if err := json.Unmarshal(result, &v2); err != nil {
			t.Fatalf("first canonical result is not valid JSON: %v", err)
		}
		result2, err2 := ir.CanonicalJSON(v2)
		if err2 != nil {
			t.Fatalf("second canonical call failed: %v", err2)
		}
		if !bytes.Equal(result, result2) {
			t.Fatalf("canonical is not idempotent: first=%s second=%s", result, result2)
		}
	})
}
