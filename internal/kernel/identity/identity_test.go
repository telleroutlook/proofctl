package identity_test

import (
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/kernel/identity"
)

func baseInputs() identity.ClaimIdentityInputs {
	return identity.ClaimIdentityInputs{
		CanonicalStatement:    "thm-main: the radius is at least 0.30",
		OrderedDepIdentities:  []string{"sha256:aaa", "sha256:bbb"},
		EvidenceDescriptors:   []identity.EvidenceDescriptor{{Role: "primitive-leaves", MediaType: "application/json", Digest: "sha256:ccc"}},
		ContractDigest:        "sha256:ddd",
		CheckerIdentityDigest: "sha256:eee",
		RuntimeIdentityDigest: "sha256:fff",
		PolicyDigest:          "sha256:ggg",
		GraphRootDigest:       "sha256:hhh",
	}
}

func TestCompute_Format(t *testing.T) {
	t.Parallel()
	d := identity.Compute(baseInputs())
	if !strings.HasPrefix(d, "sha256:") {
		t.Errorf("expected sha256: prefix, got %q", d)
	}
	if len(d) != 7+64 {
		t.Errorf("expected length %d, got %d: %q", 7+64, len(d), d)
	}
}

func TestCompute_Deterministic(t *testing.T) {
	t.Parallel()
	a := identity.Compute(baseInputs())
	b := identity.Compute(baseInputs())
	if a != b {
		t.Errorf("same inputs produced different digests: %q vs %q", a, b)
	}
}

// Each field change must produce a different digest (INV-09 prerequisite).
func TestCompute_FieldSensitivity(t *testing.T) {
	t.Parallel()
	base := identity.Compute(baseInputs())

	cases := []struct {
		name   string
		mutate func(*identity.ClaimIdentityInputs)
	}{
		{"CanonicalStatement", func(i *identity.ClaimIdentityInputs) { i.CanonicalStatement = "different" }},
		{"OrderedDepIdentities", func(i *identity.ClaimIdentityInputs) { i.OrderedDepIdentities = []string{"sha256:zzz"} }},
		{"EvidenceDescriptors_digest", func(i *identity.ClaimIdentityInputs) { i.EvidenceDescriptors[0].Digest = "sha256:zzz" }},
		{"EvidenceDescriptors_role", func(i *identity.ClaimIdentityInputs) { i.EvidenceDescriptors[0].Role = "other" }},
		{"ContractDigest", func(i *identity.ClaimIdentityInputs) { i.ContractDigest = "sha256:zzz" }},
		{"CheckerIdentityDigest", func(i *identity.ClaimIdentityInputs) { i.CheckerIdentityDigest = "sha256:zzz" }},
		{"RuntimeIdentityDigest", func(i *identity.ClaimIdentityInputs) { i.RuntimeIdentityDigest = "sha256:zzz" }},
		{"PolicyDigest", func(i *identity.ClaimIdentityInputs) { i.PolicyDigest = "sha256:zzz" }},
		{"GraphRootDigest", func(i *identity.ClaimIdentityInputs) { i.GraphRootDigest = "sha256:zzz" }},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			inp := baseInputs()
			tc.mutate(&inp)
			got := identity.Compute(inp)
			if got == base {
				t.Errorf("mutating %s did not change the digest (INV-09 violated)", tc.name)
			}
		})
	}
}

func TestCompute_EmptyInputs(t *testing.T) {
	t.Parallel()
	d := identity.Compute(identity.ClaimIdentityInputs{})
	if !strings.HasPrefix(d, "sha256:") {
		t.Errorf("expected sha256: prefix, got %q", d)
	}
}

func TestCompute_DepOrderMatters(t *testing.T) {
	t.Parallel()
	a := baseInputs()
	a.OrderedDepIdentities = []string{"sha256:aaa", "sha256:bbb"}
	da := identity.Compute(a)

	b := baseInputs()
	b.OrderedDepIdentities = []string{"sha256:bbb", "sha256:aaa"}
	db := identity.Compute(b)

	if da == db {
		t.Error("reordering dep identities should change the claim identity digest")
	}
}

func TestMustCompute_Equals_Compute(t *testing.T) {
	t.Parallel()
	inp := baseInputs()
	if identity.MustCompute(inp) != identity.Compute(inp) {
		t.Error("MustCompute must return the same value as Compute")
	}
}
