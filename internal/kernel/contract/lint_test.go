package contract_test

import (
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/kernel/contract"
)

// validContract returns a fully-valid ContractV2.
func validContract() contract.ContractV2 {
	c := contract.ContractV2{
		ContractVersion: "2",
		ClaimID:         "thm-main",
		StatementDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Obligations:     []string{"obl-integrals", "obl-remainder"},
		Checker: contract.CheckerSpec{
			Protocol:      "proofctl-checker/v2",
			CheckerDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			SchemaDigest:  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		},
		Runtime: contract.RuntimeSpec{
			Class:   "isolated-oci",
			Network: "none",
		},
		Assurance: contract.AssuranceSpec{Required: []string{"deterministic-cap"}},
	}
	c.Evidence.Mode = contract.ModeJoint
	return c
}

// ── Happy path ────────────────────────────────────────────────────────────────

func TestLintContract_Valid(t *testing.T) {
	t.Parallel()
	errs := contract.LintContract(validContract())
	if len(errs) != 0 {
		t.Errorf("expected 0 errors for valid contract, got %d: %v", len(errs), errs)
	}
}

// ── contract_version ──────────────────────────────────────────────────────────

func TestLintContract_WrongVersion(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.ContractVersion = "1"
	assertLintCode(t, c, "WRONG_VERSION")
}

func TestLintContract_EmptyVersion(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.ContractVersion = ""
	assertLintCode(t, c, "WRONG_VERSION")
}

// ── claim_id ──────────────────────────────────────────────────────────────────

func TestLintContract_MissingClaimID(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.ClaimID = ""
	assertLintCode(t, c, "MISSING")
}

// ── statement_digest ──────────────────────────────────────────────────────────

func TestLintContract_MissingStatementDigest(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.StatementDigest = ""
	assertLintCode(t, c, "MISSING")
}

func TestLintContract_ZeroStatementDigest(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.StatementDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	assertLintCode(t, c, "ZERO_DIGEST")
}

// ── obligations ───────────────────────────────────────────────────────────────

func TestLintContract_EmptyObligations(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Obligations = nil
	assertLintCode(t, c, "EMPTY")
}

func TestLintContract_DuplicateObligationID(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Obligations = []string{"obl-a", "obl-a"}
	assertLintCode(t, c, "DUPLICATE_ID")
}

func TestLintContract_EmptyObligationID(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Obligations = []string{"obl-a", ""}
	assertLintCode(t, c, "EMPTY_ID")
}

// ── checker ───────────────────────────────────────────────────────────────────

func TestLintContract_MissingCheckerDigest(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Checker.CheckerDigest = ""
	assertLintCode(t, c, "MISSING")
}

func TestLintContract_ZeroCheckerDigest(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Checker.CheckerDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	assertLintCode(t, c, "ZERO_DIGEST")
}

func TestLintContract_MissingSchemaDigest(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Checker.SchemaDigest = ""
	assertLintCode(t, c, "MISSING")
}

func TestLintContract_MissingCheckerProtocol(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Checker.Protocol = ""
	assertLintCode(t, c, "MISSING")
}

// ── runtime ───────────────────────────────────────────────────────────────────

func TestLintContract_MissingRuntimeClass(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Runtime.Class = ""
	assertLintCode(t, c, "MISSING")
}

func TestLintContract_UnknownRuntimeClass(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Runtime.Class = "docker-compose"
	assertLintCode(t, c, "UNKNOWN_CLASS")
}

// ── evidence mode ─────────────────────────────────────────────────────────────

func TestLintContract_InvalidEvidenceMode(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Evidence.Mode = "batch"
	assertLintCode(t, c, "INVALID_MODE")
}

func TestLintContract_AllValidModes(t *testing.T) {
	t.Parallel()
	for _, mode := range []contract.EvidenceMode{
		contract.ModeEach, contract.ModeJoint, contract.ModeMatrix, contract.ModeNone,
	} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			c := validContract()
			c.Evidence.Mode = mode
			errs := contract.LintContract(c)
			for _, e := range errs {
				if e.Code == "INVALID_MODE" {
					t.Errorf("mode %q should be valid, got INVALID_MODE", mode)
				}
			}
		})
	}
}

// ── evidence specs ────────────────────────────────────────────────────────────

func TestLintContract_EvidenceSpec_MissingRole(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Evidence.Mode = contract.ModeJoint
	c.Evidence.Required = []contract.EvidenceSpec{
		{Role: "", MediaType: "application/json", Digest: "sha256:dddd"},
	}
	assertLintCode(t, c, "MISSING")
}

func TestLintContract_EvidenceSpec_ZeroDigest(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Evidence.Required = []contract.EvidenceSpec{
		{
			Role:      "primitive-leaves",
			MediaType: "application/json",
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	assertLintCode(t, c, "ZERO_DIGEST")
}

// ── dependencies ─────────────────────────────────────────────────────────────

func TestLintContract_Dependency_Valid(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Dependencies = []contract.DependencySpec{
		{
			ClaimID:         "dep-lemma",
			RequiredState:   "GLOBALLY_VERIFIED",
			StatementDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		},
	}
	errs := contract.LintContract(c)
	if len(errs) != 0 {
		t.Errorf("expected 0 errors for valid dependency, got: %v", errs)
	}
}

func TestLintContract_Dependency_MissingClaimID(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Dependencies = []contract.DependencySpec{
		{
			ClaimID:         "",
			RequiredState:   "GLOBALLY_VERIFIED",
			StatementDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		},
	}
	assertLintCode(t, c, "MISSING")
}

func TestLintContract_Dependency_MissingRequiredState(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Dependencies = []contract.DependencySpec{
		{
			ClaimID:         "dep-lemma",
			RequiredState:   "",
			StatementDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		},
	}
	assertLintCode(t, c, "MISSING")
}

func TestLintContract_EmptyAssurance(t *testing.T) {
	t.Parallel()
	c := validContract()
	c.Assurance.Required = nil
	assertLintCode(t, c, "EMPTY")
}

// ── LintError.Error() ─────────────────────────────────────────────────────────

func TestLintError_ErrorString(t *testing.T) {
	t.Parallel()
	e := contract.LintError{Field: "claim_id", Code: "MISSING", Message: "claim_id must not be empty"}
	got := e.Error()
	if !strings.Contains(got, "MISSING") || !strings.Contains(got, "claim_id") {
		t.Errorf("LintError.Error() unexpected: %q", got)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func assertLintCode(t *testing.T, c contract.ContractV2, wantCode string) {
	t.Helper()
	errs := contract.LintContract(c)
	for _, e := range errs {
		if e.Code == wantCode {
			return
		}
	}
	t.Errorf("expected LintError with code %q, got: %v", wantCode, errs)
}
