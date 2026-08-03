// Package attestation manages attestation combination and self-digest computation.
package attestation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/telleroutlook/proofctl/internal/ir"
)

// GlobalAttestation is the combined result of all local attestations for a proof graph.
type GlobalAttestation struct {
	Attestations []ir.Attestation `json:"attestations"`
	SelfDigestValue string        `json:"self_digest"`
}

// Combine aggregates a slice of local attestations into a GlobalAttestation.
// It computes a self-digest over the combined payload.
func Combine(local []ir.Attestation) GlobalAttestation {
	g := GlobalAttestation{
		Attestations: local,
	}
	g.SelfDigestValue = g.SelfDigest()
	return g
}

// SelfDigest computes a SHA256 digest over the attestations payload.
// The self_digest field itself is excluded from the hash input.
func (g *GlobalAttestation) SelfDigest() string {
	// Marshal only the attestations slice, not the self_digest field.
	payload := struct {
		Attestations []ir.Attestation `json:"attestations"`
	}{
		Attestations: g.Attestations,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		panic(fmt.Sprintf("attestation: self-digest marshal: %v", err))
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}
