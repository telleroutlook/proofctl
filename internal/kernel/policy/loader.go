package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// PolicyV2File is the on-disk format for a v2 policy file.
// It is loaded strictly (unknown fields rejected) to prevent silent drift.
type PolicyV2File struct {
	Version              string              `json:"version"`
	Target               string              `json:"target"`
	AllowedAssurances    []string            `json:"allowed_assurances"`
	ForbiddenAssurances  []string            `json:"forbidden_assurances,omitempty"`
	ForbiddenRuntimes    []string            `json:"forbidden_runtimes,omitempty"`
	RequiredClaims       []string            `json:"required_claims,omitempty"`
	RequiredMetadataKeys []string            `json:"required_metadata_keys,omitempty"`
	KeyRoles             map[string][]string `json:"key_roles,omitempty"` // fingerprint → ["release-authority","checker-signer"]
}

// LoadPolicyV2 reads and strictly parses a PolicyV2File from path.
// Returns an error if the file contains unknown fields or is malformed.
func LoadPolicyV2(path string) (*PolicyV2File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	var p PolicyV2File
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: parse %s (strict): %w", path, err)
	}
	if p.Version != "2" {
		return nil, fmt.Errorf("policy: %s: version %q is not supported (want \"2\")", path, p.Version)
	}
	if p.Target == "" {
		return nil, fmt.Errorf("policy: %s: target must not be empty", path)
	}
	return &p, nil
}
