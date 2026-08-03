package qmd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/adapters/qmd"
	"github.com/telleroutlook/proofctl/internal/ir"
)

// fixtureDir returns the path to the examples/qmd directory, located relative
// to this test file.
func fixtureDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	// thisFile is adapters/qmd/adapter_test.go
	// examples/qmd is two dirs up, then examples/qmd
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "examples", "qmd")
	return root
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir(t), name))
	if err != nil {
		t.Fatalf("cannot read fixture %q: %v", name, err)
	}
	return data
}

func TestCompile_ThreeClaims(t *testing.T) {
	src := loadFixture(t, "example.pandoc.json")
	a := qmd.DefaultAdapter()
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	if pg == nil {
		t.Fatal("Compile returned nil graph")
	}
	if len(pg.Claims) != 3 {
		t.Fatalf("expected 3 claims, got %d", len(pg.Claims))
	}

	// Index claims by ID for easy lookup.
	byID := make(map[string]ir.Claim, len(pg.Claims))
	for _, c := range pg.Claims {
		byID[c.ID] = c
	}

	// def-example-frozen
	def, ok := byID["def-example-frozen"]
	if !ok {
		t.Fatal("missing claim def-example-frozen")
	}
	if def.Kind != "definition" {
		t.Errorf("def-example-frozen: expected kind=definition, got %q", def.Kind)
	}
	if len(def.DependsOn) != 0 {
		t.Errorf("def-example-frozen: expected no deps, got %v", def.DependsOn)
	}

	// lem-example-step1
	lem, ok := byID["lem-example-step1"]
	if !ok {
		t.Fatal("missing claim lem-example-step1")
	}
	if lem.Kind != "computational-lemma" {
		t.Errorf("lem-example-step1: expected kind=computational-lemma, got %q", lem.Kind)
	}
	if len(lem.DependsOn) != 1 || lem.DependsOn[0] != "def-example-frozen" {
		t.Errorf("lem-example-step1: expected deps=[def-example-frozen], got %v", lem.DependsOn)
	}

	// thm-example-main
	thm, ok := byID["thm-example-main"]
	if !ok {
		t.Fatal("missing claim thm-example-main")
	}
	if thm.Kind != "theorem" {
		t.Errorf("thm-example-main: expected kind=theorem, got %q", thm.Kind)
	}
	if len(thm.DependsOn) != 1 || thm.DependsOn[0] != "lem-example-step1" {
		t.Errorf("thm-example-main: expected deps=[lem-example-step1], got %v", thm.DependsOn)
	}
}

func TestCompile_ExtractsPandocVersion(t *testing.T) {
	src := loadFixture(t, "example.pandoc.json")
	a := qmd.DefaultAdapter()
	_, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	if len(a.Identity.PandocAPIVersion) == 0 {
		t.Fatal("expected non-nil PandocAPIVersion after Compile, got empty slice")
	}
	// Fixture uses [1, 23, 1]
	if a.Identity.PandocAPIVersion[0] != 1 {
		t.Errorf("expected PandocAPIVersion[0]=1, got %d", a.Identity.PandocAPIVersion[0])
	}
}

func TestCompile_Deterministic(t *testing.T) {
	src := loadFixture(t, "example.pandoc.json")
	a1 := qmd.DefaultAdapter()
	g1, err := a1.Compile(src)
	if err != nil {
		t.Fatalf("first Compile returned error: %v", err)
	}
	a2 := qmd.DefaultAdapter()
	g2, err := a2.Compile(src)
	if err != nil {
		t.Fatalf("second Compile returned error: %v", err)
	}
	d1, err := json.Marshal(g1)
	if err != nil {
		t.Fatalf("marshal g1: %v", err)
	}
	d2, err := json.Marshal(g2)
	if err != nil {
		t.Fatalf("marshal g2: %v", err)
	}
	if string(d1) != string(d2) {
		t.Errorf("non-deterministic output:\nfirst:  %s\nsecond: %s", d1, d2)
	}
}

func TestCompile_EmptyID_Skipped(t *testing.T) {
	// A claim Div with empty id should be skipped (no error, zero claims extracted).
	src := []byte(`{
		"pandoc-api-version": [1, 23, 1],
		"meta": {},
		"blocks": [
			{
				"t": "Div",
				"c": [
					["", ["claim"], [["kind", "lemma"]]],
					[{"t": "Para", "c": [{"t": "Str", "c": "A statement."}]}]
				]
			}
		]
	}`)
	a := qmd.DefaultAdapter()
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("expected no error for empty ID claim, got: %v", err)
	}
	if len(pg.Claims) != 0 {
		t.Errorf("expected 0 claims (empty ID skipped), got %d", len(pg.Claims))
	}
}

func TestCompile_StatementDigest(t *testing.T) {
	src := loadFixture(t, "example.pandoc.json")
	a := qmd.DefaultAdapter()
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}
	for _, c := range pg.Claims {
		want := ir.StatementDigest(c.Statement.Text)
		if c.Statement.Digest != want {
			t.Errorf("claim %q: digest mismatch: got %q, want %q", c.ID, c.Statement.Digest, want)
		}
	}
}

func TestCompile_DependsOnParsed(t *testing.T) {
	// A claim with "depends-on" containing two IDs separated by comma.
	src := []byte(`{
		"pandoc-api-version": [1, 23, 1],
		"meta": {},
		"blocks": [
			{
				"t": "Div",
				"c": [
					["claim-multi", ["claim"], [["depends-on", "dep-a, dep-b"]]],
					[{"t": "Para", "c": [{"t": "Str", "c": "A statement."}]}]
				]
			}
		]
	}`)
	a := qmd.DefaultAdapter()
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(pg.Claims))
	}
	c := pg.Claims[0]
	if len(c.DependsOn) != 2 {
		t.Fatalf("expected 2 deps, got %v", c.DependsOn)
	}
	if c.DependsOn[0] != "dep-a" {
		t.Errorf("expected dep[0]=dep-a, got %q", c.DependsOn[0])
	}
	if c.DependsOn[1] != "dep-b" {
		t.Errorf("expected dep[1]=dep-b, got %q", c.DependsOn[1])
	}
}

func TestCompile_EmptyDocument(t *testing.T) {
	src := []byte(`{"pandoc-api-version": [1, 23, 1], "meta": {}, "blocks": []}`)
	a := qmd.DefaultAdapter()
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile returned error for empty blocks: %v", err)
	}
	if len(pg.Claims) != 0 {
		t.Errorf("expected 0 claims, got %d", len(pg.Claims))
	}
}

func TestAdapterIdentityDigest_Deterministic(t *testing.T) {
	id := qmd.AdapterIdentity{
		AdapterVersion:   "1",
		PandocAPIVersion: []int{1, 23, 1},
	}
	d1 := id.Digest()
	d2 := id.Digest()
	if d1 != d2 {
		t.Errorf("digest non-deterministic: %q vs %q", d1, d2)
	}
	if d1 == "" {
		t.Error("digest is empty")
	}
}

func TestAdapterIdentityDigest_PandocVersionChanges(t *testing.T) {
	id1 := qmd.AdapterIdentity{
		AdapterVersion:   "1",
		PandocAPIVersion: []int{1, 23, 1},
	}
	id2 := qmd.AdapterIdentity{
		AdapterVersion:   "1",
		PandocAPIVersion: []int{1, 24, 0},
	}
	if id1.Digest() == id2.Digest() {
		t.Error("expected different digests for different Pandoc versions, got same")
	}
}

func TestVerifyDeterminism_Pass(t *testing.T) {
	src := loadFixture(t, "example.pandoc.json")
	a := qmd.DefaultAdapter()
	if err := a.VerifyDeterminism(src); err != nil {
		t.Errorf("VerifyDeterminism returned error for deterministic input: %v", err)
	}
}

func TestVerifyDeterminism_AlwaysPasses(t *testing.T) {
	// Inline minimal doc — must always produce the same output.
	src := []byte(`{
		"pandoc-api-version": [1, 23, 1],
		"meta": {},
		"blocks": [
			{
				"t": "Div",
				"c": [
					["lem-det", ["claim"], [["kind", "lemma"]]],
					[{"t": "Para", "c": [{"t": "Str", "c": "Determinism test statement."}]}]
				]
			}
		]
	}`)
	a := qmd.DefaultAdapter()
	for i := 0; i < 10; i++ {
		if err := a.VerifyDeterminism(src); err != nil {
			t.Errorf("iteration %d: VerifyDeterminism returned unexpected error: %v", i, err)
		}
	}
}

// TestVerifyDeterminism_InvalidJSON verifies that VerifyDeterminism returns an
// error when the input is not valid Pandoc JSON.
func TestVerifyDeterminism_InvalidJSON(t *testing.T) {
	a := qmd.DefaultAdapter()
	if err := a.VerifyDeterminism([]byte(`{bad json}`)); err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// TestCompile_InvalidJSON verifies that Compile returns an error for malformed JSON.
func TestCompile_InvalidJSON(t *testing.T) {
	a := qmd.DefaultAdapter()
	_, err := a.Compile([]byte(`{not valid}`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// TestCompile_InlineCodeAndMath verifies that Code and Math inline nodes are
// extracted as statement text.
func TestCompile_InlineCodeAndMath(t *testing.T) {
	src := []byte(`{
		"pandoc-api-version": [1, 23, 1],
		"meta": {},
		"blocks": [
			{
				"t": "Div",
				"c": [
					["lem-inline", ["claim"], []],
					[{"t": "Para", "c": [
						{"t": "Str", "c": "Let "},
						{"t": "Code", "c": [["", [], []], "f(x)"]},
						{"t": "Space"},
						{"t": "Str", "c": "and "},
						{"t": "Math", "c": [{"t": "InlineMath"}, "x^2"]},
						{"t": "SoftBreak"},
						{"t": "Str", "c": "end."}
					]}]
				]
			}
		]
	}`)
	a := qmd.DefaultAdapter()
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(pg.Claims))
	}
	text := pg.Claims[0].Statement.Text
	if text == "" {
		t.Error("expected non-empty statement text from Code/Math inlines")
	}
	// Should contain the code snippet, math, and surrounding text.
	for _, want := range []string{"f(x)", "x^2", "end."} {
		if !containsStr(text, want) {
			t.Errorf("statement text %q missing %q", text, want)
		}
	}
}

// TestCompile_LineBreak verifies that LineBreak inline is treated as a space.
func TestCompile_LineBreak(t *testing.T) {
	src := []byte(`{
		"pandoc-api-version": [1, 23, 1],
		"meta": {},
		"blocks": [
			{
				"t": "Div",
				"c": [
					["lem-lb", ["claim"], []],
					[{"t": "Para", "c": [
						{"t": "Str", "c": "first"},
						{"t": "LineBreak"},
						{"t": "Str", "c": "second"}
					]}]
				]
			}
		]
	}`)
	a := qmd.DefaultAdapter()
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(pg.Claims))
	}
	text := pg.Claims[0].Statement.Text
	if !containsStr(text, "first") || !containsStr(text, "second") {
		t.Errorf("LineBreak: statement %q missing expected words", text)
	}
}

// TestCompile_NonClaimDivIgnored verifies that a Div without class "claim"
// produces no claims (but also no error).
func TestCompile_NonClaimDivIgnored(t *testing.T) {
	src := []byte(`{
		"pandoc-api-version": [1, 23, 1],
		"meta": {},
		"blocks": [
			{
				"t": "Div",
				"c": [
					["some-id", ["note"], []],
					[{"t": "Para", "c": [{"t": "Str", "c": "Not a claim."}]}]
				]
			}
		]
	}`)
	a := qmd.DefaultAdapter()
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 0 {
		t.Errorf("expected 0 claims for non-claim div, got %d", len(pg.Claims))
	}
}

// TestCompile_MalformedDivContent verifies that a Div with malformed content
// returns an error.
func TestCompile_MalformedDivContent(t *testing.T) {
	// Div whose "c" is not a [Attr, [Block]] pair
	src := []byte(`{
		"pandoc-api-version": [1, 23, 1],
		"meta": {},
		"blocks": [{"t": "Div", "c": "not-an-array"}]
	}`)
	a := qmd.DefaultAdapter()
	_, err := a.Compile(src)
	if err == nil {
		t.Error("expected error for malformed Div content, got nil")
	}
}

// TestCompile_RequiredAssurance verifies that required-assurance KV is parsed.
func TestCompile_RequiredAssurance(t *testing.T) {
	src := []byte(`{
		"pandoc-api-version": [1, 23, 1],
		"meta": {},
		"blocks": [
			{
				"t": "Div",
				"c": [
					["lem-ra", ["claim"], [
						["kind", "lemma"],
						["required-assurance", "formal-kernel, deterministic-cap"]
					]],
					[{"t": "Para", "c": [{"t": "Str", "c": "Some text."}]}]
				]
			}
		]
	}`)
	a := qmd.DefaultAdapter()
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(pg.Claims))
	}
	c := pg.Claims[0]
	if len(c.RequiredAssurance) != 2 {
		t.Errorf("expected 2 required assurances, got %v", c.RequiredAssurance)
	}
}

// TestCompile_NoPara verifies that a claim Div with no Para block produces an
// empty statement text (not an error).
func TestCompile_NoPara(t *testing.T) {
	src := []byte(`{
		"pandoc-api-version": [1, 23, 1],
		"meta": {},
		"blocks": [
			{
				"t": "Div",
				"c": [
					["lem-nopara", ["claim"], []],
					[]
				]
			}
		]
	}`)
	a := qmd.DefaultAdapter()
	pg, err := a.Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(pg.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(pg.Claims))
	}
	if pg.Claims[0].Statement.Text != "" {
		t.Errorf("expected empty text for claim with no Para, got %q", pg.Claims[0].Statement.Text)
	}
}

func containsStr(s, sub string) bool {
	return strings.Contains(s, sub)
}
