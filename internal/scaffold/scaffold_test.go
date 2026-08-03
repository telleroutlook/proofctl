package scaffold_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/telleroutlook/proofctl/internal/scaffold"
)

// TestLookup_KnownDomains verifies that all entries in KnownDomains can be looked up.
func TestLookup_KnownDomains(t *testing.T) {
	t.Parallel()
	for _, d := range scaffold.KnownDomains {
		got, err := scaffold.Lookup(d.Name)
		if err != nil {
			t.Errorf("Lookup(%q): unexpected error: %v", d.Name, err)
		}
		if got.Name != d.Name {
			t.Errorf("Lookup(%q): got name %q", d.Name, got.Name)
		}
	}
}

// TestLookup_UnknownDomain verifies that an unknown domain returns an error.
func TestLookup_UnknownDomain(t *testing.T) {
	t.Parallel()
	_, err := scaffold.Lookup("no-such-domain")
	if err == nil {
		t.Error("Lookup(unknown): expected error, got nil")
	}
}

// TestPolicyFile_WithTemplate verifies that PolicyFile returns the expected path.
func TestPolicyFile_WithTemplate(t *testing.T) {
	t.Parallel()
	d, _ := scaffold.Lookup("cap")
	got := scaffold.PolicyFile(d)
	want := filepath.Join("policies", "cap-v1.json")
	if got != want {
		t.Errorf("PolicyFile(cap): got %q, want %q", got, want)
	}
}

// TestPolicyFile_NoTemplate verifies that PolicyFile returns "" when no template is set.
func TestPolicyFile_NoTemplate(t *testing.T) {
	t.Parallel()
	d := scaffold.Domain{Name: "bare"}
	if got := scaffold.PolicyFile(d); got != "" {
		t.Errorf("PolicyFile(bare): got %q, want empty", got)
	}
}

// TestInit_Cap verifies that Init for the cap domain writes graph.json,
// policy file, adapters/bridge.py, and negative test files.
func TestInit_Cap(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d, err := scaffold.Lookup("cap")
	if err != nil {
		t.Fatalf("Lookup(cap): %v", err)
	}
	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("Init(cap): %v", err)
	}

	for _, rel := range []string{
		"graph.json",
		filepath.Join("policies", "cap-v1.json"),
		filepath.Join("adapters", "bridge.py"),
		filepath.Join("tests", "negative", "conftest.py"),
		filepath.Join("tests", "negative", "test_tamper_basic.py"),
		filepath.Join("tests", "negative", "README.md"),
	} {
		path := filepath.Join(root, rel)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Init(cap): expected file %q was not created", rel)
		}
	}
}

// TestInit_Cap_Idempotent verifies that running Init twice does not overwrite files.
func TestInit_Cap_Idempotent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d, _ := scaffold.Lookup("cap")

	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	graphPath := filepath.Join(root, "graph.json")
	origInfo, err := os.Stat(graphPath)
	if err != nil {
		t.Fatalf("stat graph.json after first Init: %v", err)
	}

	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("second Init: %v", err)
	}
	newInfo, err := os.Stat(graphPath)
	if err != nil {
		t.Fatalf("stat graph.json after second Init: %v", err)
	}
	if origInfo.ModTime() != newInfo.ModTime() {
		t.Error("Init is not idempotent: graph.json was overwritten on second run")
	}
}

// TestInit_Lrat verifies that Init for the lrat domain writes graph.json and policy.
func TestInit_Lrat(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d, err := scaffold.Lookup("lrat")
	if err != nil {
		t.Fatalf("Lookup(lrat): %v", err)
	}
	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("Init(lrat): %v", err)
	}
	for _, rel := range []string{
		"graph.json",
		filepath.Join("policies", "lrat-v1.json"),
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); os.IsNotExist(err) {
			t.Errorf("Init(lrat): expected file %q was not created", rel)
		}
	}
	// bridge.py must NOT be written for lrat.
	if _, err := os.Stat(filepath.Join(root, "adapters", "bridge.py")); err == nil {
		t.Error("Init(lrat): adapters/bridge.py should not be written for lrat domain")
	}
}

// TestInit_Qmd verifies that Init for the qmd domain writes graph.json and policy.
func TestInit_Qmd(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d, err := scaffold.Lookup("qmd")
	if err != nil {
		t.Fatalf("Lookup(qmd): %v", err)
	}
	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("Init(qmd): %v", err)
	}
	for _, rel := range []string{
		"graph.json",
		filepath.Join("policies", "qmd-v1.json"),
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); os.IsNotExist(err) {
			t.Errorf("Init(qmd): expected file %q was not created", rel)
		}
	}
}

// TestInit_GraphJSON_IsValidJSON verifies that the written graph.json is valid JSON.
func TestInit_GraphJSON_IsValidJSON(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d, _ := scaffold.Lookup("cap")
	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("Init: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "graph.json"))
	if err != nil {
		t.Fatalf("read graph.json: %v", err)
	}
	// Minimal JSON validity check: must start with '{' or '['.
	trimmed := string(data)
	for len(trimmed) > 0 && (trimmed[0] == ' ' || trimmed[0] == '\n' || trimmed[0] == '\r' || trimmed[0] == '\t') {
		trimmed = trimmed[1:]
	}
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		t.Errorf("graph.json does not appear to be JSON: %q", string(data[:min(50, len(data))]))
	}
}

// TestInit_NoBridgeNoPolicyNegTests verifies that Init with a domain that has
// no BridgeSrc, no PolicyTemplate, and no NegativeTests writes only graph.json.
func TestInit_NoBridgeNoPolicyNegTests(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d := scaffold.Domain{
		Name:          "bare",
		GraphTemplate: "templates/lrat-graph.json",
	}
	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("Init(bare): %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "graph.json")); os.IsNotExist(err) {
		t.Error("graph.json should be created")
	}
	// No policy file, no bridge, no negative tests.
	if _, err := os.Stat(filepath.Join(root, "policies")); err == nil {
		t.Error("policies/ should not be created when no PolicyTemplate is set")
	}
	if _, err := os.Stat(filepath.Join(root, "adapters")); err == nil {
		t.Error("adapters/ should not be created when no BridgeSrc is set")
	}
}

// TestInit_NoGraphTemplate verifies that Init with no GraphTemplate skips graph.json.
func TestInit_NoGraphTemplate(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d := scaffold.Domain{
		Name:           "policy-only",
		PolicyTemplate: "templates/lrat-policy.json",
	}
	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("Init(policy-only): %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "graph.json")); err == nil {
		t.Error("graph.json should not be created when no GraphTemplate is set")
	}
	if _, err := os.Stat(filepath.Join(root, "policies", "policy-only-v1.json")); os.IsNotExist(err) {
		t.Error("policy file should be created")
	}
}

// TestInit_InvalidGraphTemplate verifies that Init returns an error when the
// graph template path does not exist in the embedded FS.
func TestInit_InvalidGraphTemplate(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d := scaffold.Domain{
		Name:          "bad",
		GraphTemplate: "templates/does-not-exist.json",
	}
	if err := scaffold.Init(root, d); err == nil {
		t.Error("Init with nonexistent GraphTemplate: expected error, got nil")
	}
}

// TestInit_InvalidPolicyTemplate verifies that Init returns an error when the
// policy template path does not exist in the embedded FS.
func TestInit_InvalidPolicyTemplate(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d := scaffold.Domain{
		Name:           "bad-policy",
		PolicyTemplate: "templates/does-not-exist-policy.json",
	}
	if err := scaffold.Init(root, d); err == nil {
		t.Error("Init with nonexistent PolicyTemplate: expected error, got nil")
	}
}

// TestInit_WritesTemplateContent verifies that the written graph.json has non-zero content.
func TestInit_WritesTemplateContent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d, _ := scaffold.Lookup("lrat")
	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("Init(lrat): %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "graph.json"))
	if err != nil {
		t.Fatalf("read graph.json: %v", err)
	}
	if len(data) == 0 {
		t.Error("graph.json should not be empty")
	}
}

// TestInit_Metamath verifies that Init for the metamath domain writes graph.json,
// policy file, and example.mm.
func TestInit_Metamath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d, err := scaffold.Lookup("metamath")
	if err != nil {
		t.Fatalf("Lookup(metamath): %v", err)
	}
	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("Init(metamath): %v", err)
	}
	for _, rel := range []string{
		"graph.json",
		filepath.Join("policies", "metamath-v1.json"),
		"example.mm",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); os.IsNotExist(err) {
			t.Errorf("Init(metamath): expected file %q was not created", rel)
		}
	}
}

// TestInit_Lean verifies that Init for the lean domain writes graph.json,
// policy file, MyProof.lean, and lakefile.lean.
func TestInit_Lean(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d, err := scaffold.Lookup("lean")
	if err != nil {
		t.Fatalf("Lookup(lean): %v", err)
	}
	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("Init(lean): %v", err)
	}
	for _, rel := range []string{
		"graph.json",
		filepath.Join("policies", "lean-v1.json"),
		"MyProof.lean",
		"lakefile.lean",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); os.IsNotExist(err) {
			t.Errorf("Init(lean): expected file %q was not created", rel)
		}
	}
}

// TestInit_Smt verifies that Init for the smt domain writes graph.json and policy.
func TestInit_Smt(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d, err := scaffold.Lookup("smt")
	if err != nil {
		t.Fatalf("Lookup(smt): %v", err)
	}
	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("Init(smt): %v", err)
	}
	for _, rel := range []string{
		"graph.json",
		filepath.Join("policies", "smt-v1.json"),
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); os.IsNotExist(err) {
			t.Errorf("Init(smt): expected file %q was not created", rel)
		}
	}
}

// TestInit_Coq verifies that Init for the coq domain writes graph.json,
// policy file, MyProof.v, and _CoqProject.
func TestInit_Coq(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	d, err := scaffold.Lookup("coq")
	if err != nil {
		t.Fatalf("Lookup(coq): %v", err)
	}
	if err := scaffold.Init(root, d); err != nil {
		t.Fatalf("Init(coq): %v", err)
	}
	for _, rel := range []string{
		"graph.json",
		filepath.Join("policies", "coq-v1.json"),
		"MyProof.v",
		"_CoqProject",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); os.IsNotExist(err) {
			t.Errorf("Init(coq): expected file %q was not created", rel)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
