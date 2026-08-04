package policy_test

import (
	"testing"

	"github.com/telleroutlook/proofctl/internal/kernel/policy"
)

func basePolicy() *policy.PolicyV2 {
	return &policy.PolicyV2{
		Version: "2",
		Target:  "thm-main",
		SigningKeyAuthorizations: []policy.KeyAuth{
			{
				KeyFingerprint:    "fp-checker",
				AllowedRoles:      []string{"checker"},
				AllowedAssurances: []string{"deterministic-cap"},
				AllowedClaimKinds: []string{"theorem", "lemma"},
				AllowedRuntimes:   []string{"isolated-oci"},
			},
			{
				KeyFingerprint:    "fp-release",
				AllowedRoles:      []string{"release-authority"},
				AllowedAssurances: []string{"deterministic-cap", "formal-kernel"},
				// empty AllowedClaimKinds → authorized for all kinds
				// empty AllowedRuntimes → authorized for all runtimes
			},
		},
		ForbiddenRuntimes: []string{"native-dev"},
	}
}

// ── IsKeyAuthorizedFor ────────────────────────────────────────────────────────

func TestIsKeyAuthorizedFor_Pass(t *testing.T) {
	t.Parallel()
	p := basePolicy()
	if !p.IsKeyAuthorizedFor("fp-checker", "deterministic-cap", "theorem", "isolated-oci") {
		t.Error("fp-checker should be authorized for deterministic-cap on theorem/isolated-oci")
	}
}

func TestIsKeyAuthorizedFor_WrongAssurance(t *testing.T) {
	t.Parallel()
	p := basePolicy()
	if p.IsKeyAuthorizedFor("fp-checker", "formal-kernel", "theorem", "isolated-oci") {
		t.Error("fp-checker must not be authorized for formal-kernel")
	}
}

func TestIsKeyAuthorizedFor_WrongClaimKind(t *testing.T) {
	t.Parallel()
	p := basePolicy()
	if p.IsKeyAuthorizedFor("fp-checker", "deterministic-cap", "axiom", "isolated-oci") {
		t.Error("fp-checker must not be authorized for claim kind 'axiom'")
	}
}

func TestIsKeyAuthorizedFor_WrongRuntime(t *testing.T) {
	t.Parallel()
	p := basePolicy()
	if p.IsKeyAuthorizedFor("fp-checker", "deterministic-cap", "theorem", "native-dev") {
		t.Error("fp-checker must not be authorized for native-dev runtime")
	}
}

func TestIsKeyAuthorizedFor_UnknownKey(t *testing.T) {
	t.Parallel()
	p := basePolicy()
	if p.IsKeyAuthorizedFor("fp-unknown", "deterministic-cap", "theorem", "isolated-oci") {
		t.Error("unknown key must not be authorized")
	}
}

func TestIsKeyAuthorizedFor_EmptyListsMeanAllAllowed(t *testing.T) {
	t.Parallel()
	// fp-release has empty AllowedClaimKinds and AllowedRuntimes → any value passes.
	p := basePolicy()
	if !p.IsKeyAuthorizedFor("fp-release", "deterministic-cap", "axiom", "native-dev") {
		t.Error("fp-release with empty kind/runtime lists should be authorized for any kind/runtime")
	}
}

func TestIsKeyAuthorizedFor_EmptyPolicy(t *testing.T) {
	t.Parallel()
	p := &policy.PolicyV2{}
	if p.IsKeyAuthorizedFor("any", "any", "any", "any") {
		t.Error("empty policy must not authorize anything")
	}
}

// ── IsForbiddenRuntime ────────────────────────────────────────────────────────

func TestIsForbiddenRuntime_Forbidden(t *testing.T) {
	t.Parallel()
	p := basePolicy()
	if !p.IsForbiddenRuntime("native-dev") {
		t.Error("native-dev must be forbidden (INV-10)")
	}
}

func TestIsForbiddenRuntime_Allowed(t *testing.T) {
	t.Parallel()
	p := basePolicy()
	if p.IsForbiddenRuntime("isolated-oci") {
		t.Error("isolated-oci must not be forbidden")
	}
}

func TestIsForbiddenRuntime_EmptyList(t *testing.T) {
	t.Parallel()
	p := &policy.PolicyV2{}
	if p.IsForbiddenRuntime("anything") {
		t.Error("empty forbidden list must not forbid anything")
	}
}
