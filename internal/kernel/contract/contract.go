// Package contract defines the Verification Contract v2 types and lint rules.
//
// A Verification Contract is the machine-readable specification for what
// a checker must prove for one claim. It declares: statement, dependencies,
// evidence mode, obligations, checker identity, runtime, assurance requirements,
// replay requirements, and independence constraints.
//
// Every claim must have exactly one Contract. Missing or invalid Contracts
// cause `proofctl contract lint` to fail, blocking release.
package contract

// EvidenceMode defines how multiple evidence pieces are combined for one invocation.
type EvidenceMode string

const (
	// ModeEach: each evidence piece runs the checker separately; all must pass.
	ModeEach EvidenceMode = "each"
	// ModeJoint: all evidence is passed to a single checker invocation.
	ModeJoint EvidenceMode = "joint"
	// ModeMatrix: a declared coverage matrix specifies which evidence covers which obligations.
	ModeMatrix EvidenceMode = "matrix"
	// ModeNone: no external evidence required (pure formal proof or axiomatic claim).
	ModeNone EvidenceMode = "none"
)

// ReplayRequirement declares the type of replay verification required.
type ReplayRequirement string

const (
	ReplayNotRequired ReplayRequirement = "not_required"
	ReplaySemantic    ReplayRequirement = "semantic"   // independent re-generation + checker re-run
	ReplayByteExact   ReplayRequirement = "byte_exact" // exact byte-for-byte digest match
)

// EvidenceSpec describes one required evidence piece in a Contract.
type EvidenceSpec struct {
	Role         string `json:"role"`
	MediaType    string `json:"media_type"`
	Digest       string `json:"digest"`
	SchemaDigest string `json:"schema_digest,omitempty"`
}

// CheckerSpec pins the checker identity for this Contract.
type CheckerSpec struct {
	Protocol                 string `json:"protocol"`
	CheckerDigest            string `json:"checker_digest"`
	BridgeDigest             string `json:"bridge_digest,omitempty"`
	SchemaDigest             string `json:"schema_digest"`
	DependencyManifestDigest string `json:"dependency_manifest_digest,omitempty"`
}

// RuntimeSpec declares the execution environment for the checker.
type RuntimeSpec struct {
	Class          string `json:"class"` // "isolated-oci" | "native-dev"
	ImageDigest    string `json:"image_digest,omitempty"`
	Network        string `json:"network"` // must be "none" for formal release
	RootFS         string `json:"rootfs"`  // "read-only" required
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	CPULimit       string `json:"cpu_limit,omitempty"`
	MemoryBytes    int64  `json:"memory_bytes,omitempty"`
}

// DependencySpec declares one required dependency claim and its minimum state.
type DependencySpec struct {
	ClaimID         string `json:"claim_id"`
	RequiredState   string `json:"required_state"` // e.g. "GLOBALLY_VERIFIED"
	StatementDigest string `json:"statement_digest"`
}

// AssuranceSpec declares what assurance types are required for release.
type AssuranceSpec struct {
	Required []string `json:"required"` // e.g. ["deterministic-cap"]
}

// IndependenceSpec declares path independence constraints.
type IndependenceSpec struct {
	Group                    string   `json:"group,omitempty"`
	ForbiddenSharedArtifacts []string `json:"forbidden_shared_artifacts,omitempty"`
	AllowedSharedDefinitions []string `json:"allowed_shared_definitions,omitempty"`
}

// ContractV2 is the complete Verification Contract for one claim.
// All fields in the Required section must be non-empty for contract lint to pass.
type ContractV2 struct {
	ContractVersion string `json:"contract_version"` // must be "2"
	ClaimID         string `json:"claim_id"`

	// StatementDigest is the sha256 of the canonical statement text.
	StatementDigest string `json:"statement_digest"`

	// Dependencies lists all claims that must reach a required state before
	// this claim's checker runs (INV-08).
	Dependencies []DependencySpec `json:"dependencies,omitempty"`

	// Evidence declares the required evidence set and how pieces are combined.
	Evidence struct {
		Mode     EvidenceMode   `json:"mode"`
		Required []EvidenceSpec `json:"required,omitempty"`
	} `json:"evidence"`

	// Checker pins the checker identity for this claim.
	Checker CheckerSpec `json:"checker"`

	// Runtime declares the execution environment.
	Runtime RuntimeSpec `json:"runtime"`

	// Obligations lists the obligation IDs that the checker must resolve.
	// The set must be non-empty and each ID must appear exactly once in
	// the checker output (INV-06).
	Obligations []string `json:"obligations"`

	// Assurance declares what assurance types are required for release.
	Assurance AssuranceSpec `json:"assurance"`

	// Replay declares byte-exact and semantic replay requirements.
	Replay struct {
		Semantic  ReplayRequirement `json:"semantic"`
		ByteExact ReplayRequirement `json:"byte_exact"`
	} `json:"replay"`

	// Independence declares path independence constraints (e.g. Path A vs Path B).
	Independence IndependenceSpec `json:"independence,omitempty"`
}
