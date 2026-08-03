package ir_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// TestResourceLimit_TooManyDependencies checks that a Claim with more than
// MaxClaimDependencies entries in depends_on fails validation.
func TestResourceLimit_TooManyDependencies(t *testing.T) {
	t.Parallel()
	deps := make([]string, ir.MaxClaimDependencies+1)
	for i := range deps {
		deps[i] = fmt.Sprintf("dep-%d", i)
	}
	c := &ir.Claim{
		ID:        "test-claim",
		Kind:      "lemma",
		DependsOn: deps,
		Statement: ir.Statement{Text: "test", Digest: ir.StatementDigest("test")},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for too many dependencies, got nil")
	}
}

// TestResourceLimit_TextTooLong checks that a Claim whose statement text exceeds
// MaxClaimTextBytes fails validation.
func TestResourceLimit_TextTooLong(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("x", ir.MaxClaimTextBytes+1)
	c := &ir.Claim{
		ID:        "test",
		Kind:      "lemma",
		Statement: ir.Statement{Text: text, Digest: ir.StatementDigest(text)},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for text too long, got nil")
	}
}

// TestResourceLimit_TooManyEvidenceRefs checks that a Claim with more than
// MaxEvidenceRefs evidence digest references fails validation.
func TestResourceLimit_TooManyEvidenceRefs(t *testing.T) {
	t.Parallel()
	evidence := make([]string, ir.MaxEvidenceRefs+1)
	for i := range evidence {
		evidence[i] = fmt.Sprintf("sha256:%064d", i)
	}
	c := &ir.Claim{
		ID:        "test",
		Kind:      "lemma",
		Evidence:  evidence,
		Statement: ir.Statement{Text: "ok", Digest: ir.StatementDigest("ok")},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for too many evidence refs, got nil")
	}
}

// TestResourceLimit_TooManyRequiredAssurances checks that a Claim with more than
// MaxAssuranceTypes required assurances fails validation.
func TestResourceLimit_TooManyRequiredAssurances(t *testing.T) {
	t.Parallel()
	assurances := make([]string, ir.MaxAssuranceTypes+1)
	for i := range assurances {
		assurances[i] = fmt.Sprintf("assurance-%d", i)
	}
	c := &ir.Claim{
		ID:                "test",
		Kind:              "lemma",
		RequiredAssurance: assurances,
		Statement:         ir.Statement{Text: "ok", Digest: ir.StatementDigest("ok")},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for too many required assurances, got nil")
	}
}

// TestResourceLimit_TooManyClaimsInGraph checks that a ProofGraph with more than
// MaxClaimsPerGraph claims fails validation.
func TestResourceLimit_TooManyClaimsInGraph(t *testing.T) {
	t.Parallel()
	claims := make([]ir.Claim, ir.MaxClaimsPerGraph+1)
	for i := range claims {
		claims[i] = ir.Claim{
			ID:        fmt.Sprintf("c%d", i),
			Kind:      "lemma",
			Statement: ir.Statement{Text: "ok", Digest: ir.StatementDigest("ok")},
		}
	}
	g := &ir.ProofGraph{Claims: claims}
	if err := g.Validate(); err == nil {
		t.Fatal("expected error for too many claims, got nil")
	}
}

// TestResourceLimit_WithinLimits checks that a well-formed Claim within all limits passes.
func TestResourceLimit_WithinLimits(t *testing.T) {
	t.Parallel()
	c := &ir.Claim{
		ID:        "valid",
		Kind:      "lemma",
		Statement: ir.Statement{Text: "short", Digest: ir.StatementDigest("short")},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid claim should pass validation: %v", err)
	}
}

// TestResourceLimit_GraphWithinLimits checks that a ProofGraph within all limits passes.
func TestResourceLimit_GraphWithinLimits(t *testing.T) {
	t.Parallel()
	g := &ir.ProofGraph{
		Claims: []ir.Claim{
			{ID: "c1", Kind: "lemma", Statement: ir.Statement{Text: "ok", Digest: ir.StatementDigest("ok")}},
			{ID: "c2", Kind: "theorem", Statement: ir.Statement{Text: "ok", Digest: ir.StatementDigest("ok")}},
		},
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("valid proof graph should pass validation: %v", err)
	}
}

// TestResourceLimit_ExactlyAtLimit checks that a Claim with exactly MaxClaimDependencies passes.
func TestResourceLimit_ExactlyAtLimit(t *testing.T) {
	t.Parallel()
	deps := make([]string, ir.MaxClaimDependencies)
	for i := range deps {
		deps[i] = fmt.Sprintf("dep-%d", i)
	}
	c := &ir.Claim{
		ID:        "test-claim",
		Kind:      "lemma",
		DependsOn: deps,
		Statement: ir.Statement{Text: "test", Digest: ir.StatementDigest("test")},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("claim at exact limit should pass: %v", err)
	}
}
