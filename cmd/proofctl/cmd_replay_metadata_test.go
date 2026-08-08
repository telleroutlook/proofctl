package main

import (
	"encoding/json"
	"testing"
)

// TestCoerceMetadataValue locks in the fix for the silent-metadata-drop bug:
// a checker emitting a non-string metadata value (float, bool, int) must be
// coerced to its string form, not cause the whole metadata map (and sibling
// obligation_results) to be dropped by a strict map[string]string unmarshal.
func TestCoerceMetadataValue(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"string", `"hello"`, "hello"},
		{"string with spaces", `"100%"`, "100%"},
		{"float", `3.14`, "3.14"},
		{"int", `42`, "42"},
		{"bool true", `true`, "true"},
		{"bool false", `false`, "false"},
		{"null", `null`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := coerceMetadataValue(json.RawMessage(tc.raw))
			if got != tc.want {
				t.Fatalf("coerceMetadataValue(%s) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestMetadataWithNonStringValuesSurvives proves the full checker-output decode:
// a metadata map with mixed value types no longer nukes obligation_results.
func TestMetadataWithNonStringValuesSurvives(t *testing.T) {
	checkerOutput := `{
		"protocol_version": 2,
		"obligation_results": [{"id": "x.obl", "verdict": "pass"}],
		"metadata": {"str_key": "hello", "float_key": 100.0, "bool_key": true}
	}`
	var out struct {
		ObligationResults []struct {
			ID      string `json:"id"`
			Verdict string `json:"verdict"`
		} `json:"obligation_results"`
		Metadata map[string]json.RawMessage `json:"metadata,omitempty"`
	}
	if err := json.Unmarshal([]byte(checkerOutput), &out); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(out.ObligationResults) != 1 {
		t.Fatalf("obligation_results dropped: got %d, want 1", len(out.ObligationResults))
	}
	meta := map[string]string{}
	for k, raw := range out.Metadata {
		meta[k] = coerceMetadataValue(raw)
	}
	if meta["float_key"] != "100.0" {
		t.Fatalf("float_key = %q, want \"100.0\"", meta["float_key"])
	}
	if meta["str_key"] != "hello" {
		t.Fatalf("str_key = %q, want \"hello\"", meta["str_key"])
	}
	if meta["bool_key"] != "true" {
		t.Fatalf("bool_key = %q, want \"true\"", meta["bool_key"])
	}
}
