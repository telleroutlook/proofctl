// Package metamath implements the Metamath proof verification adapter for proofctl.
// It maps Metamath .mm proof files to ProofGraph IR by extracting $p statements.
package metamath

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// thmLabelRe matches a Metamath $p statement and captures the theorem label.
// Format: <label> $p ... $= <proof> $.
var thmLabelRe = regexp.MustCompile(`(?m)^(\S+)\s+\$p\b`)

// MetamathAdapter parses Metamath .mm source files into ProofGraph IR.
type MetamathAdapter struct{}

// CompileGraph parses the .mm source and returns a ProofGraph with one claim
// per provable assertion ($p statement). Dependencies are not inferred from
// the proof body — each claim depends on no others by default (proofctl's DAG
// edges can be added manually in graph.json after scaffolding).
func (a *MetamathAdapter) CompileGraph(src []byte) (*ir.ProofGraph, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("metamath: empty source")
	}

	matches := thmLabelRe.FindAllSubmatch(src, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("metamath: no $p statements found in source")
	}

	seen := make(map[string]bool, len(matches))
	var claims []ir.Claim
	for _, m := range matches {
		label := strings.TrimSpace(string(m[1]))
		if seen[label] {
			continue
		}
		seen[label] = true
		claimID := "thm-" + sanitizeLabel(label)
		claims = append(claims, ir.Claim{
			ID:   claimID,
			Kind: "theorem",
			Statement: ir.Statement{
				Text:   fmt.Sprintf("Metamath theorem: %s", label),
				Digest: "sha256:" + strings.Repeat("0", 64),
			},
			DependsOn:     []string{},
			Evidence:      []string{},
			CheckerPolicy: "metamath-checker-v1",
		})
	}

	pg := &ir.ProofGraph{
		Claims: claims,
		Checkers: []ir.CheckerIdentity{
			{
				ID:              "metamath-checker-v1",
				ProtocolVersion: 1,
				CheckerDigest:   "sha256:" + strings.Repeat("0", 64),
				Runtime: ir.Runtime{
					Kind: "native",
					Cmd:  []string{"python3", "${PROOFCTL_ADAPTERS}/metamath/bridge.py"},
				},
			},
		},
		Evidence: []ir.EvidenceDescriptor{},
	}
	return pg, nil
}

// sanitizeLabel converts a Metamath theorem label to a valid claim ID by
// replacing characters not in [a-zA-Z0-9_.-] with hyphens.
func sanitizeLabel(label string) string {
	var buf bytes.Buffer
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' {
			buf.WriteRune(r)
		} else {
			buf.WriteRune('-')
		}
	}
	return buf.String()
}
