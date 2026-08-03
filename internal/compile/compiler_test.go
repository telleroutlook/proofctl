package compile

import (
	"strings"
	"testing"
)

func validGraphJSON(claims ...string) []byte {
	if len(claims) == 0 {
		claims = []string{`{"id":"c1","kind":"lemma","statement":{"text":"t","digest":"sha256:` + strings.Repeat("a", 64) + `"}}`}
	}
	claimList := strings.Join(claims, ",")
	return []byte(`{"claims":[` + claimList + `],"checkers":[],"evidence":[]}`)
}

func TestCompile_ValidJSON(t *testing.T) {
	t.Parallel()
	src := validGraphJSON()
	pg, err := Compile(src, FormatJSON)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Errorf("expected 1 claim, got %d", len(pg.Claims))
	}
	if pg.Claims[0].ID != "c1" {
		t.Errorf("claim ID: got %q want %q", pg.Claims[0].ID, "c1")
	}
}

func TestCompile_UnsupportedFormat(t *testing.T) {
	t.Parallel()
	_, err := Compile([]byte("{}"), "yaml")
	if err == nil {
		t.Fatal("expected error for unsupported format, got nil")
	}
	if !strings.Contains(err.Error(), "yaml") {
		t.Errorf("error should mention format, got: %v", err)
	}
}

func TestCompile_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := Compile([]byte("{bad json}"), FormatJSON)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestCompile_UnknownField(t *testing.T) {
	t.Parallel()
	src := []byte(`{"claims":[],"unknown_field":"bad"}`)
	_, err := Compile(src, FormatJSON)
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}

func TestCompile_EmptyClaimID(t *testing.T) {
	t.Parallel()
	src := []byte(`{"claims":[{"id":"","kind":"lemma","statement":{"text":"t","digest":"sha256:` + strings.Repeat("a", 64) + `"}}],"checkers":[],"evidence":[]}`)
	_, err := Compile(src, FormatJSON)
	if err == nil {
		t.Fatal("expected error for empty claim ID, got nil")
	}
}

func TestCompile_DuplicateClaimID(t *testing.T) {
	t.Parallel()
	claim := `{"id":"c1","kind":"lemma","statement":{"text":"t","digest":"sha256:` + strings.Repeat("a", 64) + `"}}`
	src := []byte(`{"claims":[` + claim + `,` + claim + `],"checkers":[],"evidence":[]}`)
	_, err := Compile(src, FormatJSON)
	if err == nil {
		t.Fatal("expected error for duplicate claim ID, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error should mention duplicate, got: %v", err)
	}
}

func TestCompile_UnknownDependency(t *testing.T) {
	t.Parallel()
	src := []byte(`{"claims":[{"id":"c1","kind":"lemma","depends_on":["nonexistent"],"statement":{"text":"t","digest":"sha256:` + strings.Repeat("a", 64) + `"}}],"checkers":[],"evidence":[]}`)
	_, err := Compile(src, FormatJSON)
	if err == nil {
		t.Fatal("expected error for unknown dependency, got nil")
	}
}

func TestCompile_MultipleClaims_WithDependency(t *testing.T) {
	t.Parallel()
	c1 := `{"id":"c1","kind":"lemma","statement":{"text":"t1","digest":"sha256:` + strings.Repeat("a", 64) + `"}}`
	c2 := `{"id":"c2","kind":"theorem","depends_on":["c1"],"statement":{"text":"t2","digest":"sha256:` + strings.Repeat("b", 64) + `"}}`
	src := []byte(`{"claims":[` + c1 + `,` + c2 + `],"checkers":[],"evidence":[]}`)
	pg, err := Compile(src, FormatJSON)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 2 {
		t.Errorf("expected 2 claims, got %d", len(pg.Claims))
	}
}

func TestCompile_BatchGroup_SameChecker_OK(t *testing.T) {
	t.Parallel()
	src := []byte(`{
		"claims": [
			{"id":"c1","kind":"lemma","statement":{"text":"t1","digest":"sha256:aa"},"depends_on":[],"evidence":[],"checker_policy":"ck1","batch_group":"lean-env"},
			{"id":"c2","kind":"lemma","statement":{"text":"t2","digest":"sha256:bb"},"depends_on":[],"evidence":[],"checker_policy":"ck1","batch_group":"lean-env"}
		],
		"checkers": [{"id":"ck1","protocol_version":1}],
		"evidence": []
	}`)
	pg, err := Compile(src, FormatJSON)
	if err != nil {
		t.Fatalf("expected no error for same checker in batch group, got: %v", err)
	}
	if pg.Claims[0].BatchGroup != "lean-env" {
		t.Errorf("BatchGroup not preserved: %q", pg.Claims[0].BatchGroup)
	}
}

func TestCompile_BatchGroup_DifferentChecker_Error(t *testing.T) {
	t.Parallel()
	src := []byte(`{
		"claims": [
			{"id":"c1","kind":"lemma","statement":{"text":"t1","digest":"sha256:aa"},"depends_on":[],"evidence":[],"checker_policy":"ck1","batch_group":"lean-env"},
			{"id":"c2","kind":"lemma","statement":{"text":"t2","digest":"sha256:bb"},"depends_on":[],"evidence":[],"checker_policy":"ck2","batch_group":"lean-env"}
		],
		"checkers": [{"id":"ck1","protocol_version":1},{"id":"ck2","protocol_version":1}],
		"evidence": []
	}`)
	_, err := Compile(src, FormatJSON)
	if err == nil {
		t.Error("expected error for different checker_policy in same batch_group, got nil")
	}
}
