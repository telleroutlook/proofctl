package checker

import (
	"strings"
	"testing"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// validIdentity returns a well-formed CheckerIdentity for use in tests.
func validIdentity() ir.CheckerIdentity {
	return ir.CheckerIdentity{
		ID:              "my-checker-v1",
		ProtocolVersion: 1,
		CheckerDigest:   "sha256:a3f1b2c4d5e6f7081920314253647586970a1b2c3d4e5f60718293a4b5c6d7e8",
		SchemaDigest:    "sha256:b4e2c3d4e5f6071829304152637485960718293a4b5c6d7e8f901a2b3c4d5e6f",
		Network:         "none",
		Runtime: ir.Runtime{
			Kind:   "native",
			Digest: "sha256:c5d3e4f506172839405162738495061728394051627384950617283940516273",
		},
	}
}

// TestValidate_Valid verifies that a well-formed identity returns nil.
func TestValidate_Valid(t *testing.T) {
	t.Parallel()
	if err := Validate(validIdentity()); err != nil {
		t.Errorf("expected nil for valid identity, got: %v", err)
	}
}

// TestValidate_EmptyID verifies that an empty ID returns an error.
func TestValidate_EmptyID(t *testing.T) {
	t.Parallel()
	id := validIdentity()
	id.ID = ""
	err := Validate(id)
	if err == nil {
		t.Fatal("expected error for empty ID, got nil")
	}
	if !strings.Contains(err.Error(), "ID") {
		t.Errorf("expected error to mention 'ID', got: %v", err)
	}
}

// TestValidate_ZeroProtocolVersion verifies that protocol_version == 0 returns
// an error.
func TestValidate_ZeroProtocolVersion(t *testing.T) {
	t.Parallel()
	id := validIdentity()
	id.ProtocolVersion = 0
	err := Validate(id)
	if err == nil {
		t.Fatal("expected error for protocol_version 0, got nil")
	}
	if !strings.Contains(err.Error(), "protocol_version") {
		t.Errorf("expected error to mention 'protocol_version', got: %v", err)
	}
}

// TestValidate_NegativeProtocolVersion verifies that a negative protocol
// version also returns an error.
func TestValidate_NegativeProtocolVersion(t *testing.T) {
	t.Parallel()
	id := validIdentity()
	id.ProtocolVersion = -1
	if err := Validate(id); err == nil {
		t.Fatal("expected error for negative protocol_version, got nil")
	}
}

// TestValidate_InvalidDigestFormat verifies that a checker_digest with the
// wrong format returns an error.
func TestValidate_InvalidDigestFormat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		digest string
	}{
		{"no prefix", hexStr("x")},
		{"uppercase", "sha256:" + strings.ToUpper(hexStr("x"))},
		{"too short", "sha256:abc"},
		{"wrong algorithm", "md5:" + hexStr("x")},
		{"extra chars", "sha256:" + hexStr("x") + "00"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id := validIdentity()
			id.CheckerDigest = tc.digest
			err := Validate(id)
			if err == nil {
				t.Errorf("expected error for digest %q, got nil", tc.digest)
			}
		})
	}
}

// TestValidate_ZeroDigest verifies that the all-zeros dev placeholder is
// allowed.
func TestValidate_ZeroDigest(t *testing.T) {
	t.Parallel()
	id := validIdentity()
	id.CheckerDigest = zeroCheckerDigest
	if err := Validate(id); err != nil {
		t.Errorf("expected nil for zero digest (dev placeholder), got: %v", err)
	}
}

// TestValidate_EmptyDigest verifies that an empty checker_digest is allowed
// (dev mode).
func TestValidate_EmptyDigest(t *testing.T) {
	t.Parallel()
	id := validIdentity()
	id.CheckerDigest = ""
	if err := Validate(id); err != nil {
		t.Errorf("expected nil for empty digest (dev mode), got: %v", err)
	}
}

// TestValidate_ShadowChecker verifies that the weil-shadow-v0 checker identity
// is rejected because its ProtocolVersion is 0.
// Shadow checkers bypass normal validation by being used only in shadow
// attestation paths, not through the Validate gate.
// This test documents that shadow IDs with ProtocolVersion=0 do NOT pass Validate.
func TestValidate_ShadowCheckerProtocolZero(t *testing.T) {
	t.Parallel()
	// Shadow checker has ProtocolVersion=0, which Validate rejects.
	id := ir.CheckerIdentity{
		ID:              "weil-shadow-v0",
		ProtocolVersion: 0,
		CheckerDigest:   zeroCheckerDigest,
		Network:         "none",
		Runtime:         ir.Runtime{Kind: "shadow"},
	}
	err := Validate(id)
	if err == nil {
		t.Fatal("expected error for shadow checker with ProtocolVersion=0, got nil")
	}
	if !strings.Contains(err.Error(), "protocol_version") {
		t.Errorf("expected error to mention 'protocol_version', got: %v", err)
	}
}

// TestValidate_ShadowCheckerWithVersion verifies that a shadow-style checker
// that has a non-zero protocol version and zero digest passes Validate.
func TestValidate_ShadowCheckerWithVersion(t *testing.T) {
	t.Parallel()
	id := ir.CheckerIdentity{
		ID:              "weil-shadow-v0",
		ProtocolVersion: 1,
		CheckerDigest:   zeroCheckerDigest,
		Network:         "none",
		Runtime:         ir.Runtime{Kind: "shadow"},
	}
	if err := Validate(id); err != nil {
		t.Errorf("expected nil for shadow checker with valid protocol version, got: %v", err)
	}
}

// TestValidate_InvalidNetwork verifies that an unrecognized network value
// returns an error.
func TestValidate_InvalidNetwork(t *testing.T) {
	t.Parallel()
	id := validIdentity()
	id.Network = "bridge"
	err := Validate(id)
	if err == nil {
		t.Fatal("expected error for invalid network 'bridge', got nil")
	}
	if !strings.Contains(err.Error(), "network") {
		t.Errorf("expected error to mention 'network', got: %v", err)
	}
}

// TestValidate_AllowedNetworks verifies that "none", "host", and "" are all
// accepted.
func TestValidate_AllowedNetworks(t *testing.T) {
	t.Parallel()
	for _, net := range []string{"none", "host", ""} {
		net := net
		t.Run("network="+net, func(t *testing.T) {
			t.Parallel()
			id := validIdentity()
			id.Network = net
			if err := Validate(id); err != nil {
				t.Errorf("expected nil for network %q, got: %v", net, err)
			}
		})
	}
}
