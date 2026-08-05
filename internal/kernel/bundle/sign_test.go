package bundle_test

import (
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/kernel/bundle"
)

// baseManifest returns a minimal valid Manifest for test use.
func baseManifest() *bundle.Manifest {
	return &bundle.Manifest{
		FormatVersion:          "2",
		RootClaim:              "thm-main",
		GraphRootDigest:        "sha256:aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000",
		PolicyDigest:           "sha256:bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111",
		StateDerivationVersion: "v2.0-M25",
		Members: []bundle.ManifestMemberDigest{
			{Path: "graph.json", Digest: "sha256:aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"},
			{Path: "policy.json", Digest: "sha256:bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111"},
		},
	}
}

// TestCanonicalPayload_Deterministic verifies that CanonicalPayload is
// deterministic: same manifest → same bytes every call.
func TestCanonicalPayload_Deterministic(t *testing.T) {
	t.Parallel()
	m := baseManifest()
	a, err := bundle.CanonicalPayload(m)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	b, err := bundle.CanonicalPayload(m)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(a) != string(b) {
		t.Error("CanonicalPayload: not deterministic across two calls")
	}
}

// TestCanonicalPayload_ExcludesReleaseAuthority verifies that the canonical
// payload does NOT include release_authority fields.
// This is essential: signing and verification must use the same payload,
// which cannot include the signature itself.
func TestCanonicalPayload_ExcludesReleaseAuthority(t *testing.T) {
	t.Parallel()
	m := baseManifest()
	m.ReleaseAuthority.KeyFingerprint = "a3f1b2c4d5e6f708"
	m.ReleaseAuthority.Algorithm = "ed25519"
	m.ReleaseAuthority.SignatureValue = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	payload, err := bundle.CanonicalPayload(m)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	s := string(payload)
	if strings.Contains(s, "release_authority") {
		t.Error("canonical payload must not include release_authority")
	}
	if strings.Contains(s, "a3f1b2c4d5e6f708") {
		t.Error("canonical payload must not include key fingerprint")
	}
	if strings.Contains(s, "AAAAAAA") {
		t.Error("canonical payload must not include signature value")
	}
}

// TestCanonicalPayload_IncludesAllSignedFields verifies that core fields
// appear in the payload.
func TestCanonicalPayload_IncludesAllSignedFields(t *testing.T) {
	t.Parallel()
	m := baseManifest()
	payload, err := bundle.CanonicalPayload(m)
	if err != nil {
		t.Fatalf("CanonicalPayload: %v", err)
	}
	s := string(payload)
	for _, want := range []string{"format_version", "root_claim", "graph_root_digest",
		"policy_digest", "state_derivation_version", "members"} {
		if !strings.Contains(s, want) {
			t.Errorf("canonical payload missing field %q", want)
		}
	}
}

// TestPayloadDigest_Format verifies that PayloadDigest returns a properly
// formatted sha256 digest.
func TestPayloadDigest_Format(t *testing.T) {
	t.Parallel()
	m := baseManifest()
	d, err := bundle.PayloadDigest(m)
	if err != nil {
		t.Fatalf("PayloadDigest: %v", err)
	}
	if !strings.HasPrefix(d, "sha256:") {
		t.Errorf("PayloadDigest: expected sha256: prefix, got %q", d)
	}
	hex := strings.TrimPrefix(d, "sha256:")
	if len(hex) != 64 {
		t.Errorf("PayloadDigest: expected 64 hex chars, got %d in %q", len(hex), hex)
	}
}

// TestPayloadDigest_ChangeSensitive verifies that any field change produces
// a different digest — ensuring the canonical payload covers all signed fields.
func TestPayloadDigest_ChangeSensitive(t *testing.T) {
	t.Parallel()
	m := baseManifest()
	base, _ := bundle.PayloadDigest(m)

	cases := []struct {
		name   string
		mutate func(*bundle.Manifest)
	}{
		{"root_claim", func(m *bundle.Manifest) { m.RootClaim = "thm-other" }},
		{"graph_root_digest", func(m *bundle.Manifest) { m.GraphRootDigest = "sha256:0000" }},
		{"policy_digest", func(m *bundle.Manifest) { m.PolicyDigest = "sha256:0000" }},
		{"member path", func(m *bundle.Manifest) { m.Members[0].Path = "changed.json" }},
		{"member digest", func(m *bundle.Manifest) { m.Members[0].Digest = "sha256:0000" }},
		{"add member", func(m *bundle.Manifest) {
			m.Members = append(m.Members, bundle.ManifestMemberDigest{Path: "extra.json", Digest: "sha256:cccc"})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m2 := baseManifest()
			tc.mutate(m2)
			d, _ := bundle.PayloadDigest(m2)
			if d == base {
				t.Errorf("PayloadDigest did not change after mutating %q", tc.name)
			}
		})
	}
}

// TestCanonicalPayload_ReleaseAuthorityDoesNotAffectDigest verifies that adding
// a release_authority signature does NOT change the canonical payload digest.
// This is the core invariant: sign → set field → verify must produce same digest.
func TestCanonicalPayload_ReleaseAuthorityDoesNotAffectDigest(t *testing.T) {
	t.Parallel()
	m := baseManifest()
	before, _ := bundle.PayloadDigest(m)

	m.ReleaseAuthority.KeyFingerprint = "deadbeefdeadbeef"
	m.ReleaseAuthority.Algorithm = "ed25519"
	m.ReleaseAuthority.SignatureValue = "some-signature-value"

	after, _ := bundle.PayloadDigest(m)
	if before != after {
		t.Error("PayloadDigest changed after setting ReleaseAuthority — signature is not excluded from payload")
	}
}
