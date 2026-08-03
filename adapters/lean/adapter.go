// Package lean implements the Lean 4 theorem prover adapter for the ProofGraph Engine.
// It maps Lean 4 proof files to ProofGraph IR by scanning for -- claim: <id> annotations.
// All claims in a Lean project share batch_group "lean-env" because lake build
// verifies the whole project in one invocation (M13 BatchRunner).
package lean

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/telleroutlook/proofctl/internal/ir"
)

const (
	checkerID  = "lean-checker-v1"
	batchGroup = "lean-env"
	zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

// claimAnnotationRe matches lines of the form:  -- claim: <id>
var claimAnnotationRe = regexp.MustCompile(`--\s*claim:\s*(\S+)`)

// LeanAdapter maps Lean 4 proof files to ProofGraph IR.
type LeanAdapter struct{}

// CompileGraph scans src for `-- claim: <id>` annotations and returns a
// ProofGraph with one claim per annotation. All claims are assigned to
// batch_group "lean-env" for BatchRunner dispatch.
//
// If src contains no annotations, an error is returned.
func (a *LeanAdapter) Compile(src []byte) (*ir.ProofGraph, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("lean: empty source")
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
		return nil, fmt.Errorf("lean: no '-- claim: <id>' annotations found in source")
	}

	claims := make([]ir.Claim, 0, len(claimIDs))
	for _, id := range claimIDs {
		claims = append(claims, ir.Claim{
			ID:   id,
			Kind: "theorem",
			Statement: ir.Statement{
				Text:   fmt.Sprintf("Lean 4 theorem: %s", id),
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
					Cmd:  []string{"python3", "${PROOFCTL_ADAPTERS}/lean/bridge.py"},
				},
			},
		},
		Evidence: []ir.EvidenceDescriptor{},
	}, nil
}
