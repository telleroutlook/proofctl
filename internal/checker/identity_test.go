package checker

import (
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// baseClaim returns a base Claim for testing.
func baseClaim() *ir.Claim {
	return &ir.Claim{
		ID:   "claim-base",
		Kind: "lemma",
		Statement: ir.Statement{
			Text:   "some statement",
			Digest: "sha256:" + hexStr("stmt"),
		},
	}
}

// baseChecker returns a base CheckerIdentity for testing.
func baseChecker() ir.CheckerIdentity {
	return ir.CheckerIdentity{
		ID:              "checker-1",
		ProtocolVersion: 1,
		CheckerDigest:   "sha256:" + hexStr("checker"),
		SchemaDigest:    "sha256:" + hexStr("schema"),
		Runtime: ir.Runtime{
			Kind:   "native",
			Digest: "sha256:" + hexStr("runtime"),
		},
	}
}

// hexStr returns a fixed 64-char hex string derived from a seed string
// (for use in tests where an exact value does not matter, only uniqueness).
func hexStr(seed string) string {
	base := seed
	for len(base) < 64 {
		base = base + seed
	}
	return base[:64]
}

// TestCacheKeyDeterminism checks that the same inputs always produce the same key.
func TestCacheKeyDeterminism(t *testing.T) {
	t.Parallel()
	claim := baseClaim()
	checker := baseChecker()
	evidence := []ir.EvidenceDescriptor{{Digest: "sha256:" + hexStr("ev"), Size: 42}}
	deps := []*ir.Claim{{ID: "dep1", Statement: ir.Statement{Digest: "sha256:" + hexStr("dep1")}}}

	k1 := CacheKey(claim, deps, evidence, checker, "sha256:"+hexStr("schema"), "sha256:"+hexStr("policy"))
	k2 := CacheKey(claim, deps, evidence, checker, "sha256:"+hexStr("schema"), "sha256:"+hexStr("policy"))
	if k1 != k2 {
		t.Errorf("CacheKey not deterministic: %q vs %q", k1, k2)
	}
}

// TestCacheKeyIs64CharHex checks that the returned key is a 64-character hex string.
func TestCacheKeyIs64CharHex(t *testing.T) {
	t.Parallel()
	claim := baseClaim()
	checker := baseChecker()
	k := CacheKey(claim, nil, nil, checker, "", "")
	if len(k) != 64 {
		t.Errorf("expected 64-char hex key, got len=%d: %q", len(k), k)
	}
	for _, ch := range k {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			t.Errorf("key contains non-hex character %q: %q", ch, k)
			break
		}
	}
}

// TestCacheKeyChangesOnClaimID checks that changing the claim ID changes the key.
func TestCacheKeyChangesOnClaimID(t *testing.T) {
	t.Parallel()
	c1 := baseClaim()
	c2 := baseClaim()
	c2.ID = "different-claim-id"
	checker := baseChecker()

	k1 := CacheKey(c1, nil, nil, checker, "", "")
	k2 := CacheKey(c2, nil, nil, checker, "", "")
	if k1 == k2 {
		t.Error("expected different key when claim ID changes, got same")
	}
}

// TestCacheKeyChangesOnStatementDigest checks that changing the statement digest changes the key.
func TestCacheKeyChangesOnStatementDigest(t *testing.T) {
	t.Parallel()
	c1 := baseClaim()
	c2 := baseClaim()
	c2.Statement.Digest = "sha256:" + hexStr("different-stmt")
	checker := baseChecker()

	k1 := CacheKey(c1, nil, nil, checker, "", "")
	k2 := CacheKey(c2, nil, nil, checker, "", "")
	if k1 == k2 {
		t.Error("expected different key when statement digest changes, got same")
	}
}

// TestCacheKeyChangesOnDependencyDigest checks that changing a dependency digest changes the key.
func TestCacheKeyChangesOnDependencyDigest(t *testing.T) {
	t.Parallel()
	claim := baseClaim()
	checker := baseChecker()

	deps1 := []*ir.Claim{{ID: "dep1", Statement: ir.Statement{Digest: "sha256:" + hexStr("dep1a")}}}
	deps2 := []*ir.Claim{{ID: "dep1", Statement: ir.Statement{Digest: "sha256:" + hexStr("dep1b")}}}

	k1 := CacheKey(claim, deps1, nil, checker, "", "")
	k2 := CacheKey(claim, deps2, nil, checker, "", "")
	if k1 == k2 {
		t.Error("expected different key when dependency digest changes, got same")
	}
}

// TestCacheKeyChangesOnEvidenceDigest checks that changing evidence digest changes the key.
func TestCacheKeyChangesOnEvidenceDigest(t *testing.T) {
	t.Parallel()
	claim := baseClaim()
	checker := baseChecker()

	ev1 := []ir.EvidenceDescriptor{{Digest: "sha256:" + hexStr("ev1"), Size: 100}}
	ev2 := []ir.EvidenceDescriptor{{Digest: "sha256:" + hexStr("ev2"), Size: 100}}

	k1 := CacheKey(claim, nil, ev1, checker, "", "")
	k2 := CacheKey(claim, nil, ev2, checker, "", "")
	if k1 == k2 {
		t.Error("expected different key when evidence digest changes, got same")
	}
}

// TestCacheKeyChangesOnCheckerDigest checks that changing the checker digest changes the key.
func TestCacheKeyChangesOnCheckerDigest(t *testing.T) {
	t.Parallel()
	claim := baseClaim()
	ch1 := baseChecker()
	ch2 := baseChecker()
	ch2.CheckerDigest = "sha256:" + hexStr("different-checker")

	k1 := CacheKey(claim, nil, nil, ch1, "", "")
	k2 := CacheKey(claim, nil, nil, ch2, "", "")
	if k1 == k2 {
		t.Error("expected different key when checker digest changes, got same")
	}
}

// TestCacheKeyChangesOnProtocolVersion checks that changing the protocol version changes the key.
func TestCacheKeyChangesOnProtocolVersion(t *testing.T) {
	t.Parallel()
	claim := baseClaim()
	ch1 := baseChecker()
	ch2 := baseChecker()
	ch2.ProtocolVersion = 999

	k1 := CacheKey(claim, nil, nil, ch1, "", "")
	k2 := CacheKey(claim, nil, nil, ch2, "", "")
	if k1 == k2 {
		t.Error("expected different key when protocol version changes, got same")
	}
}

// TestCacheKeyChangesOnRuntimeKind checks that changing the runtime kind changes the key.
func TestCacheKeyChangesOnRuntimeKind(t *testing.T) {
	t.Parallel()
	claim := baseClaim()
	ch1 := baseChecker()
	ch2 := baseChecker()
	ch2.Runtime.Kind = "wasi"

	k1 := CacheKey(claim, nil, nil, ch1, "", "")
	k2 := CacheKey(claim, nil, nil, ch2, "", "")
	if k1 == k2 {
		t.Error("expected different key when runtime kind changes, got same")
	}
}

// TestCacheKeyChangesOnSchemaDigest checks that changing the schema digest changes the key.
func TestCacheKeyChangesOnSchemaDigest(t *testing.T) {
	t.Parallel()
	claim := baseClaim()
	checker := baseChecker()

	k1 := CacheKey(claim, nil, nil, checker, "sha256:"+hexStr("schema1"), "")
	k2 := CacheKey(claim, nil, nil, checker, "sha256:"+hexStr("schema2"), "")
	if k1 == k2 {
		t.Error("expected different key when schema digest changes, got same")
	}
}

// TestCacheKeyChangesOnPolicyDigest checks that changing the policy digest changes the key.
func TestCacheKeyChangesOnPolicyDigest(t *testing.T) {
	t.Parallel()
	claim := baseClaim()
	checker := baseChecker()

	k1 := CacheKey(claim, nil, nil, checker, "", "sha256:"+hexStr("policy1"))
	k2 := CacheKey(claim, nil, nil, checker, "", "sha256:"+hexStr("policy2"))
	if k1 == k2 {
		t.Error("expected different key when policy digest changes, got same")
	}
}

// TestCacheKeyEmptyDepsEvidence checks that empty deps/evidence produce a valid key without panic.
func TestCacheKeyEmptyDepsEvidence(t *testing.T) {
	t.Parallel()
	claim := baseClaim()
	checker := baseChecker()

	// Must not panic.
	k := CacheKey(claim, nil, nil, checker, "", "")
	if len(k) != 64 {
		t.Errorf("expected 64-char key, got %d: %q", len(k), k)
	}

	k2 := CacheKey(claim, []*ir.Claim{}, []ir.EvidenceDescriptor{}, checker, "", "")
	// nil and empty slice may or may not produce the same key depending on JSON marshaling.
	// Both must be valid 64-char hex strings.
	if len(k2) != 64 {
		t.Errorf("expected 64-char key for empty slices, got %d: %q", len(k2), k2)
	}
}

// TestCacheKeyWithToolchain_DiffersFromWithout verifies that a toolchain map
// produces a different cache key than no toolchain.
func TestCacheKeyWithToolchain_DiffersFromWithout(t *testing.T) {
	t.Parallel()
	claim := &ir.Claim{ID: "c1", Kind: "lemma", Statement: ir.Statement{Digest: "sha256:aa"}}
	checker := ir.CheckerIdentity{ID: "ck1", ProtocolVersion: 1}

	k1 := CacheKey(claim, nil, nil, checker, "", "")
	k2 := CacheKeyWithToolchain(claim, nil, nil, checker, "", "", map[string]string{
		"lean_version": "4.14.0",
	})
	if k1 == k2 {
		t.Error("CacheKeyWithToolchain should differ from CacheKey when toolchain is non-empty")
	}
}

// TestCacheKeyWithToolchain_DiffersOnToolchainChange verifies that a different
// toolchain produces a different cache key.
func TestCacheKeyWithToolchain_DiffersOnToolchainChange(t *testing.T) {
	t.Parallel()
	claim := &ir.Claim{ID: "c1", Kind: "lemma", Statement: ir.Statement{Digest: "sha256:aa"}}
	checker := ir.CheckerIdentity{ID: "ck1", ProtocolVersion: 1}

	k1 := CacheKeyWithToolchain(claim, nil, nil, checker, "", "", map[string]string{
		"lean_version": "4.14.0",
	})
	k2 := CacheKeyWithToolchain(claim, nil, nil, checker, "", "", map[string]string{
		"lean_version": "4.15.0",
	})
	if k1 == k2 {
		t.Error("different toolchain versions should produce different cache keys")
	}
}

// TestCacheKeyWithToolchain_NilEqualsEmpty verifies that nil and empty toolchain
// produce the same cache key as CacheKey.
func TestCacheKeyWithToolchain_NilEqualsEmpty(t *testing.T) {
	t.Parallel()
	claim := &ir.Claim{ID: "c1", Kind: "lemma", Statement: ir.Statement{Digest: "sha256:aa"}}
	checker := ir.CheckerIdentity{ID: "ck1", ProtocolVersion: 1}

	kBase := CacheKey(claim, nil, nil, checker, "", "")
	kNil := CacheKeyWithToolchain(claim, nil, nil, checker, "", "", nil)
	kEmpty := CacheKeyWithToolchain(claim, nil, nil, checker, "", "", map[string]string{})

	if kBase != kNil {
		t.Error("CacheKeyWithToolchain(nil) should equal CacheKey")
	}
	if kBase != kEmpty {
		t.Error("CacheKeyWithToolchain(empty map) should equal CacheKey")
	}
}
