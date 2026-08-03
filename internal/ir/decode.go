// Package ir defines the Intermediate Representation types for the ProofGraph Engine.
package ir

import (
	"encoding/json"
	"fmt"
	"io"
)

// DecodeStrict decodes a single JSON value of type T from r.
// It rejects unknown fields and returns an error if the input contains
// trailing data after the first value.
func DecodeStrict[T any](r io.Reader) (T, error) {
	var zero T
	dec := json.NewDecoder(r)
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
