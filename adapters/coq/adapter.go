// Package coq implements the Coq/Rocq proof assistant adapter for proofctl.
// It maps Coq .v theorem files to ProofGraph IR by scanning for
// (* claim: <id> *) annotations. All claims share batch_group "coq-env"
// because coqchk verifies all .vo files in a single invocation (M13 BatchRunner).
package coq

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/telleroutlook/proofctl/internal/ir"
)

const (
	checkerID  = "coq-checker-v1"
	batchGroup = "coq-env"
	zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

// claimAnnotationRe matches Coq block comments of the form: (* claim: <id> *)
var claimAnnotationRe = regexp.MustCompile(`\(\*\s*claim:\s*(\S+)\s*\*\)`)

// CoqAdapter maps Coq .v source files to ProofGraph IR.
type CoqAdapter struct{}

// Compile scans src for (* claim: <id> *) annotations and returns a ProofGraph
// with one claim per annotation, all assigned to batch_group "coq-env".
func (a *CoqAdapter) Compile(src []byte) (*ir.ProofGraph, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("coq: empty source")
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
		id := strings.TrimSpace(m[1])
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		claimIDs = append(claimIDs, id)
	}

	if len(claimIDs) == 0 {
		return nil, fmt.Errorf("coq: no '(* claim: <id> *)' annotations found in source")
	}

	claims := make([]ir.Claim, 0, len(claimIDs))
	for _, id := range claimIDs {
		claims = append(claims, ir.Claim{
			ID:   id,
			Kind: "theorem",
			Statement: ir.Statement{
				Text:   fmt.Sprintf("Coq theorem: %s", id),
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
					Cmd:  []string{"python3", "${PROOFCTL_ADAPTERS}/coq/bridge.py"},
				},
			},
		},
		Evidence: []ir.EvidenceDescriptor{},
	}, nil
}
