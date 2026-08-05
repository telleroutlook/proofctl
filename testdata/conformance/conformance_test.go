// Package conformance contains protocol v2 conformance test vectors for all
// supported domain adapters (cap, lrat, qmd, metamath, lean, coq, smt, isabelle).
//
// Each vector specifies a checker output JSON and the expected validation result.
// Vectors are defined inline to avoid file-system dependencies and run as unit tests.
//
// Canvas §9/M34: all supported domains must have conformance vectors.
package conformance

import (
	"strings"
	"testing"

	v2 "github.com/telleroutlook/proofctl/pkg/protocol/v2"
)

type conformanceVector struct {
	name        string
	domain      string
	output      v2.CheckerOutputV2
	obligations []string // nil means skip exact-set check
	wantPass    bool
	wantErrCode string // substring expected in error when wantPass==false
}

var vectors = []conformanceVector{
	// ── CAP domain ────────────────────────────────────────────────────────────
	{
		name:   "cap/valid-pass",
		domain: "cap",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-main",
			ObligationResults: []v2.ObligationResult{
				{ID: "d1.normalization-schema-valid", Verdict: "pass"},
				{ID: "d1.primitive-set-complete", Verdict: "pass"},
			},
		},
		obligations: []string{"d1.normalization-schema-valid", "d1.primitive-set-complete"},
		wantPass:    true,
	},
	{
		name:   "cap/fail-obligation",
		domain: "cap",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-main",
			ObligationResults: []v2.ObligationResult{
				{ID: "d1.normalization-schema-valid", Verdict: "fail"},
				{ID: "d1.primitive-set-complete", Verdict: "pass"},
			},
		},
		obligations: []string{"d1.normalization-schema-valid", "d1.primitive-set-complete"},
		wantPass:    false,
	},
	{
		name:   "cap/missing-obligation",
		domain: "cap",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-main",
			ObligationResults: []v2.ObligationResult{
				{ID: "d1.normalization-schema-valid", Verdict: "pass"},
				// d1.primitive-set-complete missing
			},
		},
		obligations: []string{"d1.normalization-schema-valid", "d1.primitive-set-complete"},
		wantPass:    false,
		wantErrCode: "OBLIGATION_MISSING",
	},
	{
		name:   "cap/extra-obligation",
		domain: "cap",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-main",
			ObligationResults: []v2.ObligationResult{
				{ID: "d1.normalization-schema-valid", Verdict: "pass"},
				{ID: "d1.primitive-set-complete", Verdict: "pass"},
				{ID: "d1.undeclared-extra", Verdict: "pass"},
			},
		},
		obligations: []string{"d1.normalization-schema-valid", "d1.primitive-set-complete"},
		wantPass:    false,
		wantErrCode: "OBLIGATION_EXTRA",
	},
	// ── LRAT domain ───────────────────────────────────────────────────────────
	{
		name:   "lrat/valid-pass",
		domain: "lrat",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-unsat",
			ObligationResults: []v2.ObligationResult{
				{ID: "lrat.formula-parsed", Verdict: "pass"},
				{ID: "lrat.proof-checked", Verdict: "pass"},
			},
		},
		obligations: []string{"lrat.formula-parsed", "lrat.proof-checked"},
		wantPass:    true,
	},
	// ── Metamath domain ────────────────────────────────────────────────────────
	{
		name:   "metamath/valid-pass",
		domain: "metamath",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-mp",
			ObligationResults: []v2.ObligationResult{
				{ID: "mm.theorem-exists", Verdict: "pass"},
				{ID: "mm.proof-verifies", Verdict: "pass"},
			},
		},
		obligations: []string{"mm.theorem-exists", "mm.proof-verifies"},
		wantPass:    true,
	},
	{
		name:   "metamath/fail-proof",
		domain: "metamath",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-mp",
			ObligationResults: []v2.ObligationResult{
				{ID: "mm.theorem-exists", Verdict: "pass"},
				{ID: "mm.proof-verifies", Verdict: "fail"},
			},
		},
		obligations: []string{"mm.theorem-exists", "mm.proof-verifies"},
		wantPass:    false,
	},
	// ── QMD domain ────────────────────────────────────────────────────────────
	{
		name:   "qmd/valid-pass",
		domain: "qmd",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-main",
			ObligationResults: []v2.ObligationResult{
				{ID: "qmd.document-parsed", Verdict: "pass"},
				{ID: "qmd.claims-verified", Verdict: "pass"},
			},
		},
		obligations: []string{"qmd.document-parsed", "qmd.claims-verified"},
		wantPass:    true,
	},
	// ── SMT domain ────────────────────────────────────────────────────────────
	{
		name:   "smt/valid-pass",
		domain: "smt",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-unsat",
			ObligationResults: []v2.ObligationResult{
				{ID: "smt.formula-parsed", Verdict: "pass"},
				{ID: "smt.proof-checked", Verdict: "pass"},
			},
		},
		obligations: []string{"smt.formula-parsed", "smt.proof-checked"},
		wantPass:    true,
	},
	// ── Lean domain (stub) ────────────────────────────────────────────────────
	{
		name:   "lean/valid-pass",
		domain: "lean",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-main",
			ObligationResults: []v2.ObligationResult{
				{ID: "lean.build-succeeded", Verdict: "pass"},
			},
		},
		obligations: []string{"lean.build-succeeded"},
		wantPass:    true,
	},
	// ── Coq domain (stub) ─────────────────────────────────────────────────────
	{
		name:   "coq/valid-pass",
		domain: "coq",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-main",
			ObligationResults: []v2.ObligationResult{
				{ID: "coq.coqchk-passed", Verdict: "pass"},
			},
		},
		obligations: []string{"coq.coqchk-passed"},
		wantPass:    true,
	},
	// ── Isabelle domain (stub) ────────────────────────────────────────────────
	{
		name:   "isabelle/valid-pass",
		domain: "isabelle",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-main",
			ObligationResults: []v2.ObligationResult{
				{ID: "isabelle.session-built", Verdict: "pass"},
			},
		},
		obligations: []string{"isabelle.session-built"},
		wantPass:    true,
	},
	// ── Cross-domain: wrong claim_id ──────────────────────────────────────────
	{
		name:   "cross-domain/wrong-claim-id",
		domain: "cap",
		output: v2.CheckerOutputV2{
			ProtocolVersion: 2,
			ClaimID:         "thm-wrong",
			ObligationResults: []v2.ObligationResult{
				{ID: "d1.normalization-schema-valid", Verdict: "pass"},
			},
		},
		obligations: []string{"d1.normalization-schema-valid"},
		wantPass:    false,
		wantErrCode: "CLAIM_ID_MISMATCH",
	},
}

func TestConformanceVectors(t *testing.T) {
	for _, vec := range vectors {
		t.Run(vec.name, func(t *testing.T) {
			t.Parallel()
			// Use the claim_id from the vector itself as the expected ID,
			// EXCEPT for the cross-domain/wrong-claim-id test.
			expectedClaimID := vec.output.ClaimID
			if vec.wantErrCode == "CLAIM_ID_MISMATCH" {
				expectedClaimID = "thm-main" // what was requested
			}

			err := v2.ValidateOutput(vec.output, expectedClaimID, vec.obligations)
			if err == nil {
				// Validation passed — check obligation results.
				pass := v2.AllObligationsPass(vec.output)
				if vec.wantPass && !pass {
					t.Errorf("vector %q: expected all obligations to pass, got failures", vec.name)
				}
				if !vec.wantPass && vec.wantErrCode == "" && pass {
					t.Errorf("vector %q: expected obligation failure, but all passed", vec.name)
				}
			} else {
				if vec.wantPass {
					t.Errorf("vector %q: unexpected validation error: %v", vec.name, err)
				}
				if vec.wantErrCode != "" && !strings.Contains(err.Error(), vec.wantErrCode) {
					t.Errorf("vector %q: expected error containing %q, got: %v",
						vec.name, vec.wantErrCode, err)
				}
			}
		})
	}
}
