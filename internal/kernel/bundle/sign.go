package bundle

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// manifestSignPayload is the canonical payload for manifest signing.
// It includes all fields EXCEPT release_authority (which holds the signature).
type manifestSignPayload struct {
	FormatVersion          string                 `json:"format_version"`
	RootClaim              string                 `json:"root_claim"`
	GraphRootDigest        string                 `json:"graph_root_digest"`
	PolicyDigest           string                 `json:"policy_digest"`
	StateDerivationVersion string                 `json:"state_derivation_version"`
	Members                []ManifestMemberDigest `json:"members"`
}

// CanonicalPayload returns the canonical JSON bytes of m (excluding release_authority).
// This is the message that must be signed and verified.
func CanonicalPayload(m *Manifest) ([]byte, error) {
	p := manifestSignPayload{
		FormatVersion:          m.FormatVersion,
		RootClaim:              m.RootClaim,
		GraphRootDigest:        m.GraphRootDigest,
		PolicyDigest:           m.PolicyDigest,
		StateDerivationVersion: m.StateDerivationVersion,
		Members:                m.Members,
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("bundle: canonical payload: %w", err)
	}
	return data, nil
}

// PayloadDigest returns "sha256:<hex>" of the canonical payload.
func PayloadDigest(m *Manifest) (string, error) {
	data, err := CanonicalPayload(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum), nil
}
