// Package scaffold generates project scaffolding for proofctl domains.
// It embeds all domain templates and the CAP bridge into the binary so that
// "proofctl init --domain <name>" works offline with no external dependencies.
package scaffold

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed templates
var templates embed.FS

// Domain describes a supported proofctl domain.
type Domain struct {
	// Name is the short identifier used with --domain.
	Name string
	// Description is a one-line human-readable summary.
	Description string
	// PolicyTemplate is the relative path inside templates/ for the policy JSON.
	PolicyTemplate string
	// GraphTemplate is the relative path inside templates/ for the graph JSON.
	GraphTemplate string
	// BridgeSrc is the path of the bridge script relative to the repo root,
	// embedded separately via BridgeFS (may be empty if not applicable).
	BridgeSrc string
	// NegativeTests indicates whether to scaffold tests/negative/ on init.
	NegativeTests bool
	// ExtraTemplates maps destination path (relative to project root) →
	// source path inside templates/. Written after graph/policy/bridge.
	ExtraTemplates map[string]string
}

//go:embed bridge.py
var bridgeFS embed.FS

// KnownDomains is the registry of all built-in proofctl domains.
var KnownDomains = []Domain{
	{
		Name:           "cap",
		Description:    "Computer-Assisted Proof via JSON certificate + standalone checker (e.g. interval arithmetic, LDL^T)",
		PolicyTemplate: "templates/cap-policy.json",
		GraphTemplate:  "templates/cap-graph.json",
		BridgeSrc:      "bridge.py",
		NegativeTests:  true,
	},
	{
		Name:           "lrat",
		Description:    "LRAT SAT solver domain: formula → unsat → verified 3-claim graph",
		PolicyTemplate: "templates/lrat-policy.json",
		GraphTemplate:  "templates/lrat-graph.json",
	},
	{
		Name:           "qmd",
		Description:    "Quarto/Pandoc QMD document: extract claims from <div class=\"claim\"> blocks",
		PolicyTemplate: "templates/qmd-policy.json",
		GraphTemplate:  "templates/qmd-graph.json",
	},
	{
		Name:           "metamath",
		Description:    "Metamath formal proof domain: verify .mm proof files using the metamath checker",
		PolicyTemplate: "templates/metamath-policy.json",
		GraphTemplate:  "templates/metamath-graph.json",
		ExtraTemplates: map[string]string{
			"example.mm": "templates/metamath-example.mm",
		},
	},
	{
		Name:           "smt",
		Description:    "SMT/Alethe/DRAT domain: verify SMT-LIB2 unsatisfiability via Alethe or DRAT proof certificates",
		PolicyTemplate: "templates/smt-policy.json",
		GraphTemplate:  "templates/smt-graph.json",
	},
	{
		Name:           "lean",
		Description:    "Lean 4 formal proof domain: verify theorems via lake build; uses BatchGroup for whole-project verification",
		PolicyTemplate: "templates/lean-policy.json",
		GraphTemplate:  "templates/lean-graph.json",
		ExtraTemplates: map[string]string{
			"MyProof.lean":  "templates/lean-MyProof.lean",
			"lakefile.lean": "templates/lean-lakefile.lean",
		},
	},
	{
		Name:           "coq",
		Description:    "Coq/Rocq formal proof domain: verify .vo objects via coqchk; uses BatchGroup for whole-project verification",
		PolicyTemplate: "templates/coq-policy.json",
		GraphTemplate:  "templates/coq-graph.json",
		ExtraTemplates: map[string]string{
			"MyProof.v":   "templates/coq-MyProof.v",
			"_CoqProject": "templates/coq-_CoqProject",
		},
	},
}

// Lookup returns the Domain for name, or an error if unknown.
func Lookup(name string) (Domain, error) {
	for _, d := range KnownDomains {
		if d.Name == name {
			return d, nil
		}
	}
	return Domain{}, fmt.Errorf("scaffold: unknown domain %q (known: cap, lrat, qmd, metamath, smt, lean, coq)", name)
}

// Init writes all scaffold files for domain into root.
// It creates:
//
//	<root>/graph.json               — claim graph template
//	<root>/policies/<domain>-v1.json — release policy template
//	<root>/adapters/bridge.py       — CAP bridge (CAP domain only)
//
// Files are written with mode 0644. Existing files are not overwritten.
func Init(root string, d Domain) error {
	if d.GraphTemplate != "" {
		if err := writeTemplate(root, "graph.json", d.GraphTemplate); err != nil {
			return err
		}
	}
	if d.PolicyTemplate != "" {
		policyDst := filepath.Join("policies", d.Name+"-v1.json")
		if err := writeTemplate(root, policyDst, d.PolicyTemplate); err != nil {
			return err
		}
	}
	if d.BridgeSrc != "" {
		if err := writeBridge(root, d.BridgeSrc); err != nil {
			return err
		}
	}
	if d.NegativeTests {
		if err := writeNegativeTests(root); err != nil {
			return err
		}
	}
	for dst, src := range d.ExtraTemplates {
		if err := writeTemplate(root, dst, src); err != nil {
			return err
		}
	}
	return nil
}

// PolicyFile returns the relative path (from project root) to the generated
// policy file for domain d.
func PolicyFile(d Domain) string {
	if d.PolicyTemplate == "" {
		return ""
	}
	return filepath.Join("policies", d.Name+"-v1.json")
}

// writeTemplate reads src from the embedded templates FS and writes it to
// filepath.Join(root, dst), creating parent directories as needed.
// No-ops if the destination already exists.
func writeTemplate(root, dst, src string) error {
	dstPath := filepath.Join(root, dst)
	if _, err := os.Stat(dstPath); err == nil {
		return nil // already exists — don't overwrite
	}
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return fmt.Errorf("scaffold: mkdir %s: %w", filepath.Dir(dstPath), err)
	}
	data, err := fs.ReadFile(templates, src)
	if err != nil {
		return fmt.Errorf("scaffold: read template %s: %w", src, err)
	}
	if err := os.WriteFile(dstPath, data, 0o644); err != nil {
		return fmt.Errorf("scaffold: write %s: %w", dstPath, err)
	}
	return nil
}

// writeNegativeTests writes the generic tamper test templates to <root>/tests/negative/.
func writeNegativeTests(root string) error {
	for _, name := range []string{"conftest.py", "test_tamper_basic.py", "README.md"} {
		if err := writeTemplate(root, filepath.Join("tests", "negative", name),
			filepath.Join("templates", "negative", name)); err != nil {
			return err
		}
	}
	return nil
}

// <root>/adapters/bridge.py with mode 0755 (executable).
// No-ops if the destination already exists.
func writeBridge(root, src string) error {
	dstPath := filepath.Join(root, "adapters", "bridge.py")
	if _, err := os.Stat(dstPath); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Join(root, "adapters"), 0o755); err != nil {
		return fmt.Errorf("scaffold: mkdir adapters: %w", err)
	}
	data, err := fs.ReadFile(bridgeFS, src)
	if err != nil {
		return fmt.Errorf("scaffold: read bridge %s: %w", src, err)
	}
	if err := os.WriteFile(dstPath, data, 0o755); err != nil {
		return fmt.Errorf("scaffold: write bridge.py: %w", err)
	}
	return nil
}
