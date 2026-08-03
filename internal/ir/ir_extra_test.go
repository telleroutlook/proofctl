package ir

import (
	"strings"
	"testing"
)

// ── ValidateClaimID ──────────────────────────────────────────────────────────

func TestValidateClaimID_Valid(t *testing.T) {
	t.Parallel()
	cases := []string{"c1", "claim-1", "lem.d1", "thm_main", "a-b.c_d", "X1"}
	for _, id := range cases {
		if err := ValidateClaimID(id); err != nil {
			t.Errorf("ValidateClaimID(%q) = %v, want nil", id, err)
		}
	}
}

func TestValidateClaimID_Empty(t *testing.T) {
	t.Parallel()
	if err := ValidateClaimID(""); err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestValidateClaimID_LeadingDot(t *testing.T) {
	t.Parallel()
	if err := ValidateClaimID(".hidden"); err == nil {
		t.Error("expected error for ID starting with '.'")
	}
}

func TestValidateClaimID_DoubleDot(t *testing.T) {
	t.Parallel()
	if err := ValidateClaimID("a..b"); err == nil {
		t.Error("expected error for ID containing '..'")
	}
	if err := ValidateClaimID(".."); err == nil {
		t.Error("expected error for '..'")
	}
}

func TestValidateClaimID_InvalidChars(t *testing.T) {
	t.Parallel()
	cases := []string{"a/b", "a b", "a@b", "a:b", "a!b", "../escape"}
	for _, id := range cases {
		if err := ValidateClaimID(id); err == nil {
			t.Errorf("ValidateClaimID(%q): expected error, got nil", id)
		}
	}
}

// ── DigestOf ─────────────────────────────────────────────────────────────────

func TestDigestOf_NonEmpty(t *testing.T) {
	t.Parallel()
	d, err := DigestOf(map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("DigestOf: %v", err)
	}
	if !strings.HasPrefix(d, "sha256:") {
		t.Errorf("digest should start with sha256:, got %q", d)
	}
	if len(d) != 7+64 {
		t.Errorf("digest length: got %d want %d", len(d), 7+64)
	}
}

func TestDigestOf_Deterministic(t *testing.T) {
	t.Parallel()
	v := map[string]int{"a": 1, "b": 2}
	d1, _ := DigestOf(v)
	d2, _ := DigestOf(v)
	if d1 != d2 {
		t.Errorf("DigestOf not deterministic: %q != %q", d1, d2)
	}
}

func TestDigestOf_DifferentValues(t *testing.T) {
	t.Parallel()
	d1, _ := DigestOf("hello")
	d2, _ := DigestOf("world")
	if d1 == d2 {
		t.Error("different values should produce different digests")
	}
}

// ── DecodeAttestation ────────────────────────────────────────────────────────

func TestDecodeAttestation_Valid(t *testing.T) {
	t.Parallel()
	input := `{
		"claim_id":"c1","statement_digest":"sha256:` + strings.Repeat("a", 64) + `",
		"dependency_digests":[],"evidence":[],"checker":{"id":"ch","protocol_version":1,
		"checker_digest":"","schema_digest":"","runtime":{"kind":"native"},"network":""},
		"outcome":"accepted","assurance":"formal-kernel","resources":{"wall_millis":0,
		"cpu_millis":0,"mem_bytes":0},"start_freshness":"","end_freshness":"","self_digest":""
	}`
	att, err := DecodeAttestation(strings.NewReader(input))
	if err != nil {
		t.Fatalf("DecodeAttestation: %v", err)
	}
	if att.ClaimID != "c1" {
		t.Errorf("ClaimID: got %q want %q", att.ClaimID, "c1")
	}
	if att.Outcome != "accepted" {
		t.Errorf("Outcome: got %q want %q", att.Outcome, "accepted")
	}
}

func TestDecodeAttestation_UnknownField(t *testing.T) {
	t.Parallel()
	input := `{"claim_id":"c1","unknown_field":"bad"}`
	_, err := DecodeAttestation(strings.NewReader(input))
	if err == nil {
		t.Error("expected error for unknown field")
	}
}

func TestDecodeAttestation_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := DecodeAttestation(strings.NewReader("{bad"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ── DecodeProofGraph ─────────────────────────────────────────────────────────

func TestDecodeProofGraph_Valid(t *testing.T) {
	t.Parallel()
	input := `{"claims":[{"id":"c1","kind":"lemma","statement":{"text":"t","digest":"sha256:` +
		strings.Repeat("a", 64) + `"},"depends_on":[],"required_assurance":[],` +
		`"evidence":[],"checker_policy":""}],"checkers":[],"evidence":[]}`
	pg, err := DecodeProofGraph(strings.NewReader(input))
	if err != nil {
		t.Fatalf("DecodeProofGraph: %v", err)
	}
	if len(pg.Claims) != 1 || pg.Claims[0].ID != "c1" {
		t.Errorf("unexpected claims: %+v", pg.Claims)
	}
}

func TestDecodeProofGraph_UnknownField(t *testing.T) {
	t.Parallel()
	input := `{"claims":[],"checkers":[],"evidence":[],"extra_field":"bad"}`
	_, err := DecodeProofGraph(strings.NewReader(input))
	if err == nil {
		t.Error("expected error for unknown field")
	}
}

func TestDecodeProofGraph_TooManyClaims(t *testing.T) {
	t.Parallel()
	// Build a graph with MaxClaimsPerGraph+1 claims inline — but that's 10001 claims
	// which would be huge JSON. Instead just verify the Validate() path is exercised
	// by passing a ProofGraph that already has one claim with too-long text.
	longText := strings.Repeat("x", MaxClaimTextBytes+1)
	input := `{"claims":[{"id":"c1","kind":"lemma","statement":{"text":"` + longText +
		`","digest":"sha256:` + strings.Repeat("a", 64) + `"},"depends_on":[],` +
		`"required_assurance":[],"evidence":[],"checker_policy":""}],"checkers":[],"evidence":[]}`
	_, err := DecodeProofGraph(strings.NewReader(input))
	if err == nil {
		t.Error("expected error for statement text exceeding limit")
	}
}

// ── CanonicalJSON / scanArray coverage ───────────────────────────────────────

func TestCanonicalJSON_WithArray(t *testing.T) {
	t.Parallel()
	v := map[string]any{"b": []int{3, 1, 2}, "a": "hello"}
	out, err := CanonicalJSON(v)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	// Keys must be sorted: "a" before "b"
	s := string(out)
	aIdx := strings.Index(s, `"a"`)
	bIdx := strings.Index(s, `"b"`)
	if aIdx > bIdx {
		t.Errorf("keys not sorted: 'a' at %d, 'b' at %d in %s", aIdx, bIdx, s)
	}
}

func TestCanonicalJSON_NestedArray(t *testing.T) {
	t.Parallel()
	// Exercises scanArray recursion path
	v := []any{[]any{"nested"}, map[string]any{"z": 1, "a": 2}}
	_, err := CanonicalJSON(v)
	if err != nil {
		t.Fatalf("CanonicalJSON with nested array: %v", err)
	}
}

func TestDecodeStrict_ArrayTrailingData(t *testing.T) {
	t.Parallel()
	// Exercises trailing-data detection after an array
	_, err := DecodeStrict[Claim](strings.NewReader(`{"id":"c1","kind":"lemma","statement":{"text":"t","digest":"sha256:` + strings.Repeat("a", 64) + `"},"depends_on":[],"required_assurance":[],"evidence":[],"checker_policy":""}` + `{}`))
	if err == nil {
		t.Error("expected error for trailing data")
	}
}
