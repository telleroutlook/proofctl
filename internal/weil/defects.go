// Package weil provides Weil-specific claim graph compilation and defect mapping.
package weil

// Defect represents a known Weil verification defect.
type Defect struct {
	ID          string // e.g. "D4"
	ClaimID     string // maps to the ProofGraph claim ID
	Description string // human-readable failure reason
	BlockReason string // stable machine-readable blocker string
}

// KnownDefects is the authoritative list of Weil D-number defects.
// These represent known failures in the Weil Phase B verification.
// Each one, if unresolved, must prevent thm-main-radius-030 from being released.
var KnownDefects = []Defect{
	{
		ID:          "D1",
		ClaimID:     "lem-d1-normalization",
		Description: "Input primitives normalization not verified by v2 checker",
		BlockReason: "D1: normalization check missing in v2 certificate schema",
	},
	{
		ID:          "D2",
		ClaimID:     "lem-d2-weil-reduction",
		Description: "Weil explicit formula reduction step not formally verified",
		BlockReason: "D2: weil-reduction has no deterministic-cap attestation",
	},
	{
		ID:          "D3",
		ClaimID:     "lem-d3-legendre",
		Description: "Legendre symbol computation not independently checked",
		BlockReason: "D3: legendre checker result not in v2 certificate",
	},
	{
		ID:          "D4",
		ClaimID:     "lem-d4-kernel-bound",
		Description: "Kernel bound computation: expected primitive set not fully verified; colluding tamper possible",
		BlockReason: "D4: kernel-bound expected primitive keys not matched; v1/v2 checker result conflict",
	},
	{
		ID:          "D5",
		ClaimID:     "lem-d5-log-moments",
		Description: "Log-moment integrals not verified with frozen parameter set",
		BlockReason: "D5: log-moment integrals missing frozen-parameter attestation",
	},
	{
		ID:          "D6",
		ClaimID:     "lem-path-a-primitives",
		Description: "Path A primitive integral set incomplete or unverified",
		BlockReason: "D6: Path A primitive keys do not match expected set",
	},
	{
		ID:          "D7",
		ClaimID:     "lem-path-b-primitives",
		Description: "Path B primitive integral set incomplete or unverified",
		BlockReason: "D7: Path B primitive keys do not match expected set",
	},
	{
		ID:          "D8",
		ClaimID:     "lem-ab-intersection",
		Description: "Path A/B key intersection is empty; no common primitives verified",
		BlockReason: "D8: Path A keys and Path B keys share no common primitives; intersection empty",
	},
	{
		ID:          "D9",
		ClaimID:     "lem-matrix-reconstruction",
		Description: "Matrix reconstruction by checker not confirmed against certificate",
		BlockReason: "D9: checker-reconstructed matrix digest does not match certificate",
	},
	{
		ID:          "D10",
		ClaimID:     "lem-interval-ldlt",
		Description: "Rational interval LDLT decomposition not verified",
		BlockReason: "D10: interval LDLT checker did not produce accepted outcome",
	},
	{
		ID:          "D18",
		ClaimID:     "thm-main-radius-030",
		Description: "Main theorem: certified_radius not established; all D4/D8 blockers unresolved",
		BlockReason: "D18: thm-main-radius-030 blocked — D4 and D8 unresolved; no certified radius",
	},
}

// DefectsByClaimID returns a map from claim ID to Defect for fast lookup.
func DefectsByClaimID() map[string]Defect {
	m := make(map[string]Defect, len(KnownDefects))
	for _, d := range KnownDefects {
		m[d.ClaimID] = d
	}
	return m
}

// DefectsByID returns a map from D-number (e.g. "D4") to Defect.
func DefectsByID() map[string]Defect {
	m := make(map[string]Defect, len(KnownDefects))
	for _, d := range KnownDefects {
		m[d.ID] = d
	}
	return m
}
