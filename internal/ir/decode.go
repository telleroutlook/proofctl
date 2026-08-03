// Package ir defines the Intermediate Representation types for the ProofGraph Engine.
package ir

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// maxDecodeBytes is the maximum input size accepted by DecodeStrict (64 MiB).
const maxDecodeBytes = 64 * 1024 * 1024

// DecodeStrict decodes a single JSON value of type T from r.
// It rejects unknown fields, rejects duplicate keys, and returns an error if
// the input contains trailing data after the first value.
func DecodeStrict[T any](r io.Reader) (T, error) {
	var zero T

	// Buffer the full input with a size limit.
	lr := io.LimitReader(r, maxDecodeBytes+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return zero, fmt.Errorf("decode: read: %w", err)
	}
	if len(buf) > maxDecodeBytes {
		return zero, fmt.Errorf("decode: input exceeds %d byte limit", maxDecodeBytes)
	}

	// Detect duplicate keys at any nesting level.
	if err := checkDuplicateKeys(buf); err != nil {
		return zero, err
	}

	// Decode with unknown-field rejection.
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields()
	var v T
	if err := dec.Decode(&v); err != nil {
		return zero, fmt.Errorf("decode: %w", err)
	}
	// Ensure no trailing data follows the decoded value.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return zero, fmt.Errorf("decode: unexpected trailing data after JSON value")
	}
	return v, nil
}

// checkDuplicateKeys walks the JSON token stream and returns an error on the
// first duplicate key found at any object nesting level.
func checkDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	_, err := scanValue(dec)
	return err
}

// scanValue reads one complete JSON value from dec.
// Returns the token that ended the value (for callers that need it) and any error.
func scanValue(dec *json.Decoder) (json.Token, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}

	delim, ok := tok.(json.Delim)
	if !ok {
		// Scalar value — nothing more to do.
		return tok, nil
	}

	switch delim {
	case '{':
		return nil, scanObject(dec)
	case '[':
		return nil, scanArray(dec)
	}
	// '}' or ']' — closing delimiter; return it to the caller.
	return tok, nil
}

// scanObject reads the contents of a JSON object from dec (opening '{' already consumed).
// Returns an error on duplicate keys or any parse error.
func scanObject(dec *json.Decoder) error {
	seen := make(map[string]struct{})
	for dec.More() {
		// Read key.
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("ir: expected string key, got %T", keyTok)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("ir: duplicate key %q in JSON object", key)
		}
		seen[key] = struct{}{}

		// Read value (recurse for nested objects/arrays).
		if _, err := scanValue(dec); err != nil {
			return err
		}
	}
	// Consume closing '}'.
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// scanArray reads the contents of a JSON array from dec (opening '[' already consumed).
func scanArray(dec *json.Decoder) error {
	for dec.More() {
		if _, err := scanValue(dec); err != nil {
			return err
		}
	}
	// Consume closing ']'.
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// DecodeClaim decodes a Claim with strict field validation.
func DecodeClaim(r io.Reader) (*Claim, error) {
	c, err := DecodeStrict[Claim](r)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// DecodeAttestation decodes an Attestation with strict field validation.
func DecodeAttestation(r io.Reader) (*Attestation, error) {
	a, err := DecodeStrict[Attestation](r)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// DecodeProofGraph decodes a ProofGraph with strict field validation.
func DecodeProofGraph(r io.Reader) (*ProofGraph, error) {
	pg, err := DecodeStrict[ProofGraph](r)
	if err != nil {
		return nil, err
	}
	return &pg, nil
}
