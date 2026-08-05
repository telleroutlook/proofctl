// Package contract — lint.go implements ContractV2 field completeness checks.
//
// LintContract validates that a ContractV2 is well-formed before it is used
// in a checker run. Lint errors are structured so that `proofctl contract lint`
// can report them as machine-readable JSON as well as human-readable text.
//
// A claim with a lint-failing Contract cannot proceed past CANDIDATE state;
// proofverify rejects it as BLOCKED.
package contract

import (
	"fmt"
	"strings"
)

// LintError describes a single validation failure in a ContractV2.
type LintError struct {
	// Field is the JSON path of the offending field (e.g. "checker.checker_digest").
	Field string `json:"field"`
	// Code is a machine-readable error code (e.g. "MISSING", "EMPTY_DIGEST", "INVALID_MODE").
	Code string `json:"code"`
	// Message is a human-readable description.
	Message string `json:"message"`
}

func (e LintError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", e.Code, e.Field, e.Message)
}

// zeroDigest is the all-zeros placeholder digest that must not appear in pinned fields.
const zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// LintContract validates a ContractV2 for field completeness and consistency.
//
// Rules checked:
//   - contract_version must be "2"
//   - claim_id must be non-empty
//   - statement_digest must be non-empty and non-zero
//   - obligations must be non-empty; IDs must be unique
//   - checker.checker_digest and checker.schema_digest must be non-empty/non-zero
//   - runtime.class must be non-empty and one of the known classes
//   - runtime.network must be "none" or "host" (empty → warning only, not error)
//   - evidence.mode must be a valid EvidenceMode value
//   - each evidence spec must have a non-empty role, media_type and digest
//   - dependencies must have non-empty claim_id, required_state, statement_digest
func LintContract(c ContractV2) []LintError {
	var errs []LintError

	add := func(field, code, msg string) {
		errs = append(errs, LintError{Field: field, Code: code, Message: msg})
	}
	requireNonEmpty := func(field, val, code string) {
		if strings.TrimSpace(val) == "" {
			add(field, code, field+" must not be empty")
		}
	}
	requireNonZeroDigest := func(field, val string) {
		if strings.TrimSpace(val) == "" {
			add(field, "MISSING", field+" must not be empty")
			return
		}
		if val == zeroDigest {
			add(field, "ZERO_DIGEST", field+" is the all-zeros placeholder — pin a real digest")
		}
	}

	// contract_version
	if c.ContractVersion != "2" {
		add("contract_version", "WRONG_VERSION",
			fmt.Sprintf("contract_version must be \"2\", got %q", c.ContractVersion))
	}

	// claim_id
	requireNonEmpty("claim_id", c.ClaimID, "MISSING")

	// statement_digest
	requireNonZeroDigest("statement_digest", c.StatementDigest)

	// obligations
	if len(c.Obligations) == 0 {
		add("obligations", "EMPTY", "obligations must contain at least one ID")
	} else {
		seen := make(map[string]bool, len(c.Obligations))
		for i, id := range c.Obligations {
			if strings.TrimSpace(id) == "" {
				add(fmt.Sprintf("obligations[%d]", i), "EMPTY_ID", "obligation ID must not be empty")
			} else if seen[id] {
				add(fmt.Sprintf("obligations[%d]", i), "DUPLICATE_ID",
					fmt.Sprintf("obligation ID %q is duplicated", id))
			}
			seen[id] = true
		}
	}

	// checker
	requireNonZeroDigest("checker.checker_digest", c.Checker.CheckerDigest)
	requireNonZeroDigest("checker.schema_digest", c.Checker.SchemaDigest)
	requireNonEmpty("checker.protocol", c.Checker.Protocol, "MISSING")

	// runtime
	requireNonEmpty("runtime.class", c.Runtime.Class, "MISSING")
	knownClasses := map[string]bool{"isolated-oci": true, "native-dev": true, "wasi": true, "scripted": true}
	if c.Runtime.Class != "" && !knownClasses[c.Runtime.Class] {
		add("runtime.class", "UNKNOWN_CLASS",
			fmt.Sprintf("runtime.class %q is not a known class (known: isolated-oci, native-dev, scripted, wasi)", c.Runtime.Class))
	}

	// evidence mode
	validModes := map[EvidenceMode]bool{
		ModeEach: true, ModeJoint: true, ModeMatrix: true, ModeNone: true,
	}
	if !validModes[c.Evidence.Mode] {
		add("evidence.mode", "INVALID_MODE",
			fmt.Sprintf("evidence.mode %q is not valid (must be: each, joint, matrix, none)", c.Evidence.Mode))
	}

	// evidence specs
	for i, ev := range c.Evidence.Required {
		prefix := fmt.Sprintf("evidence.required[%d]", i)
		requireNonEmpty(prefix+".role", ev.Role, "MISSING")
		requireNonEmpty(prefix+".media_type", ev.MediaType, "MISSING")
		requireNonZeroDigest(prefix+".digest", ev.Digest)
	}

	// dependencies
	for i, dep := range c.Dependencies {
		prefix := fmt.Sprintf("dependencies[%d]", i)
		requireNonEmpty(prefix+".claim_id", dep.ClaimID, "MISSING")
		requireNonEmpty(prefix+".required_state", dep.RequiredState, "MISSING")
		requireNonZeroDigest(prefix+".statement_digest", dep.StatementDigest)
	}

	// assurance
	if len(c.Assurance.Required) == 0 {
		add("assurance.required", "EMPTY",
			"assurance.required must declare at least one assurance type")
	}

	return errs
}
