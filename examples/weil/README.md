# Weil Shadow Integration Example

## Overview

This directory contains an example showing how to integrate proofctl with a
Weil Phase B proof output in shadow mode.

Shadow mode runs the full release gate evaluation — all checkers, all digest
verifications, all assurance checks — but does not set `certified_radius` to
a non-null value or trigger any downstream release actions. It is the
recommended way to start before all claims are accepted.

## Usage

```bash
# Initialize a proof graph project
proofctl init

# Compile the Weil Phase B output to ProofGraph IR
proofctl compile --format weil weil-phase-b-output.json

# Check the status of all claims
proofctl status --json

# Run the release gate in shadow mode (does not write a real release)
proofctl release --shadow --json

# Check which claims are not yet accepted
proofctl frontier thm-main-radius-030

# See what claims are affected by a specific claim
proofctl impact lem-d1-normalization
```

## Expected Output (shadow mode, before all claims are accepted)

```json
{
  "certified_radius": null,
  "released": false,
  "policy_version": "1",
  "blockers": [
    "required claim \"lem-d1-normalization\" has no attestation",
    "required claim \"thm-main-radius-030\" has no attestation"
  ]
}
```

## Weil Phase B Adapter

The `adapters/weil` package maps Weil Phase B structured output to the
ProofGraph IR. See `adapters/weil/adapter.go` for the stub implementation.
The full adapter will be implemented as the Weil Phase B output format is
finalized.

## References

- [Weil Acceptance Criteria](../../docs/WEIL_ACCEPTANCE.md)
- [ProofGraph IR](../../docs/PROOFGRAPH_IR.md)
- [Assurance Model](../../docs/ASSURANCE_MODEL.md)
