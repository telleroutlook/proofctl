// Package isabelle implements the Isabelle/HOL proof assistant adapter for proofctl.
// It maps Isabelle .thy theory files to ProofGraph IR by scanning for
// (* claim: <id> *) or -- claim: <id> annotations.
// All claims share batch_group "isabelle-env" because isabelle build
// verifies the whole session in one invocation (M13 BatchRunner).
package isabelle

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/telleroutlook/proofctl/internal/ir"
)

const (
	checkerID  = "isabelle-checker-v1"
	batchGroup = "isabelle-env"
	zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

// claimAnnotationRe matches both annotation styles in .thy files:
//
//	(* claim: <id> *)   — Isabelle/ML block comment
//	-- claim: <id>      — Isabelle line comment (Isar syntax)
var claimAnnotationRe = regexp.MustCompile(
	`(?:\(\*\s*claim:\s*(\S+)\s*\*\)|--\s*claim:\s*(\S+))`,
)

// IsabelleAdapter maps Isabelle .thy source files to ProofGraph IR.
type IsabelleAdapter struct{}

// Compile scans src for claim annotations and returns a ProofGraph with one
// claim per annotation, all assigned to batch_group "isabelle-env".
func (a *IsabelleAdapter) Compile(src []byte) (*ir.ProofGraph, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("isabelle: empty source")
	}

	var claimIDs []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(src))
	for scanner.Scan() {
		line := scanner.Text()
		m := claimAnnotationRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// m[1] = block comment match, m[2] = line comment match.
		id := strings.TrimSpace(m[1])
		if id == "" {
			id = strings.TrimSpace(m[2])
		}
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		claimIDs = append(claimIDs, id)
	}

	if len(claimIDs) == 0 {
		return nil, fmt.Errorf("isabelle: no claim annotations found (use '(* claim: <id> *)' or '-- claim: <id>')")
	}

	claims := make([]ir.Claim, 0, len(claimIDs))
	for _, id := range claimIDs {
		claims = append(claims, ir.Claim{
			ID:   id,
			Kind: "theorem",
			Statement: ir.Statement{
				Text:   fmt.Sprintf("Isabelle/HOL theorem: %s", id),
				Digest: zeroDigest,
			},
			DependsOn:     []string{},
			Evidence:      []string{},
			CheckerPolicy: checkerID,
			BatchGroup:    batchGroup,
		})
	}

	return &ir.ProofGraph{
		Claims: claims,
		Checkers: []ir.CheckerIdentity{
			{
				ID:              checkerID,
				ProtocolVersion: 1,
				CheckerDigest:   zeroDigest,
				Runtime: ir.Runtime{
					Kind: "native",
					Cmd:  []string{"python3", "${PROOFCTL_ADAPTERS}/isabelle/bridge.py"},
				},
			},
		},
		Evidence: []ir.EvidenceDescriptor{},
	}, nil
}
