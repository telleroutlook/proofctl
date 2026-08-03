package ir

import (
	"strings"
	"testing"
)

// TestDecodeStrictValidJSON checks that a valid JSON input decodes correctly.
func TestDecodeStrictValidJSON(t *testing.T) {
	t.Parallel()
	input := `{"id":"c1","kind":"lemma","statement":{"text":"foo","digest":"sha256:abc"},"depends_on":[],"required_assurance":[],"evidence":[],"checker_policy":""}`
	got, err := DecodeStrict[Claim](strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "c1" {
		t.Errorf("ID: got %q want %q", got.ID, "c1")
	}
	if got.Kind != "lemma" {
		t.Errorf("Kind: got %q want %q", got.Kind, "lemma")
	}
	if got.Statement.Text != "foo" {
		t.Errorf("Statement.Text: got %q want %q", got.Statement.Text, "foo")
	}
}

// TestDecodeStrictUnknownField checks that an unknown field causes an error.
func TestDecodeStrictUnknownField(t *testing.T) {
	t.Parallel()
	input := `{"id":"c1","unknown_field":"bad"}`
	_, err := DecodeStrict[Claim](strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}

// TestDecodeStrictDuplicateKey documents Go's stdlib behavior on duplicate keys.
// Go's json.Decoder uses the last value for duplicate keys (no error is raised).
// TODO: implement duplicate key detection
func TestDecodeStrictDuplicateKey(t *testing.T) {
	t.Parallel()
	// Go's encoding/json silently accepts duplicate keys and uses the last value.
	input := `{"id":"first","id":"second","kind":"lemma","statement":{"text":"","digest":""},"depends_on":[],"required_assurance":[],"evidence":[],"checker_policy":""}`
	got, err := DecodeStrict[Claim](strings.NewReader(input))
	// Document actual behavior: no error, last value wins.
	if err != nil {
		t.Logf("Note: got unexpected error on duplicate key: %v", err)
		return
	}
	// The last "id" value wins.
	if got.ID != "second" {
		t.Errorf("duplicate key: expected last value %q, got %q", "second", got.ID)
	}
}

// TestDecodeStrictEmptyReader checks that an empty reader returns an error.
func TestDecodeStrictEmptyReader(t *testing.T) {
	t.Parallel()
	_, err := DecodeStrict[Claim](strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error for empty reader, got nil")
	}
}

// TestDecodeStrictTruncatedJSON checks that truncated JSON returns an error.
func TestDecodeStrictTruncatedJSON(t *testing.T) {
	t.Parallel()
	input := `{"id":"c1","kind":"lemma"`
	_, err := DecodeStrict[Claim](strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for truncated JSON, got nil")
	}
}

// TestDecodeStrictTrailingGarbage checks that trailing data after valid JSON returns an error.
func TestDecodeStrictTrailingGarbage(t *testing.T) {
	t.Parallel()
	input := `{"id":"c1","kind":"lemma","statement":{"text":"","digest":""},"depends_on":[],"required_assurance":[],"evidence":[],"checker_policy":""} trailing-garbage`
	_, err := DecodeStrict[Claim](strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for trailing garbage, got nil")
	}
}

// TestDecodeStrictFullClaim checks that a full valid Claim round-trips through DecodeStrict.
func TestDecodeStrictFullClaim(t *testing.T) {
	t.Parallel()
	input := `{
		"id": "claim-1",
		"kind": "theorem",
		"statement": {"text": "some statement", "digest": "sha256:abcdef"},
		"depends_on": ["dep-1", "dep-2"],
		"required_assurance": ["formal-kernel"],
		"evidence": ["sha256:evid1"],
		"checker_policy": "strict"
	}`
	got, err := DecodeStrict[Claim](strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "claim-1" {
		t.Errorf("ID: got %q want %q", got.ID, "claim-1")
	}
	if got.Kind != "theorem" {
		t.Errorf("Kind: got %q want %q", got.Kind, "theorem")
	}
	if len(got.DependsOn) != 2 {
		t.Errorf("DependsOn length: got %d want 2", len(got.DependsOn))
	}
	if len(got.RequiredAssurance) != 1 {
		t.Errorf("RequiredAssurance length: got %d want 1", len(got.RequiredAssurance))
	}
	if got.CheckerPolicy != "strict" {
		t.Errorf("CheckerPolicy: got %q want %q", got.CheckerPolicy, "strict")
	}
}

// TestDecodeStrictMissingRequiredFields checks that missing fields decode to zero values
// (Go does not enforce required fields via JSON decoding).
func TestDecodeStrictMissingRequiredFields(t *testing.T) {
	t.Parallel()
	// Only "id" is present; all other fields will be zero-valued.
	input := `{"id":"only-id"}`
	got, err := DecodeStrict[Claim](strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "only-id" {
		t.Errorf("ID: got %q want %q", got.ID, "only-id")
	}
	// Zero-value checks.
	if got.Kind != "" {
		t.Errorf("Kind should be empty, got %q", got.Kind)
	}
	if len(got.DependsOn) != 0 {
		t.Errorf("DependsOn should be nil/empty, got %v", got.DependsOn)
	}
}

// TestDecodeClaimHelperValid tests the DecodeClaim helper.
func TestDecodeClaimHelperValid(t *testing.T) {
	t.Parallel()
	input := `{"id":"c2","kind":"axiom","statement":{"text":"base","digest":"sha256:00"},"depends_on":[],"required_assurance":[],"evidence":[],"checker_policy":""}`
	c, err := DecodeClaim(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil claim")
	}
	if c.ID != "c2" {
		t.Errorf("ID: got %q want %q", c.ID, "c2")
	}
}

// TestDecodeClaimHelperUnknownField tests that DecodeClaim rejects unknown fields.
func TestDecodeClaimHelperUnknownField(t *testing.T) {
	t.Parallel()
	input := `{"id":"c1","bogus_field":true}`
	_, err := DecodeClaim(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}

// TestDecodeStrictTrailingWhitespace checks that trailing whitespace is allowed
// (it is not "data" in JSON terms and should not trigger trailing-data error).
func TestDecodeStrictTrailingWhitespace(t *testing.T) {
	t.Parallel()
	input := `{"id":"c1","kind":"","statement":{"text":"","digest":""},"depends_on":[],"required_assurance":[],"evidence":[],"checker_policy":""}   `
	_, err := DecodeStrict[Claim](strings.NewReader(input))
	if err != nil {
		t.Errorf("unexpected error for trailing whitespace: %v", err)
	}
}

// TestDecodeStrictTwoObjects checks that two concatenated JSON objects trigger trailing-data error.
func TestDecodeStrictTwoObjects(t *testing.T) {
	t.Parallel()
	input := `{"id":"c1","kind":"","statement":{"text":"","digest":""},"depends_on":[],"required_assurance":[],"evidence":[],"checker_policy":""}{"id":"c2"}`
	_, err := DecodeStrict[Claim](strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for two concatenated objects, got nil")
	}
}
