// Package ir defines the Intermediate Representation types for the ProofGraph Engine.
package ir

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalJSON returns a deterministic, compact JSON encoding of v.
// Map keys are sorted alphabetically. Struct fields follow json tag order.
// This is used for cache key computation and attestation self-digests.
func CanonicalJSON(v any) ([]byte, error) {
	// Marshal to intermediate representation, then re-sort any map keys.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("ir: canonical marshal: %w", err)
	}
	return sortJSONKeys(raw)
}

// DigestOf returns the sha256 digest (as "sha256:<hex>") of the canonical JSON of v.
func DigestOf(v any) (string, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// StatementDigest computes the canonical digest of a Statement's text field.
func StatementDigest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// sortJSONKeys recursively re-encodes a JSON value with sorted object keys.
func sortJSONKeys(raw []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	sorted := sortValue(v)
	return json.Marshal(sorted)
}

func sortValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(val))
		for _, k := range keys {
			out[k] = sortValue(val[k])
		}
		return out
	case []any:
		for i, elem := range val {
			val[i] = sortValue(elem)
		}
		return val
	default:
		return v
	}
}
