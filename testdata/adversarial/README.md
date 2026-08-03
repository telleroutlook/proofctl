# Adversarial Test Fixtures

These fixtures represent known attack vectors and malformed inputs used to verify
fail-closed behavior throughout the ProofGraph Engine.

**All fixtures in this directory are expected to be REJECTED by the system.**
They must never be used as passing inputs.

## Fixture Inventory

| File | Type | Attack Vector |
|---|---|---|
| `claim_unknown_field.json` | Claim | Extra `"injected_status"` field — must be rejected by `DecodeStrict` |
| `claim_duplicate_key.json` | Claim | Duplicate `"id"` key — second value differs from first |
| `dag_cycle.json` | ProofGraph | Claim A depends on B and B depends on A — cycle |
| `dag_missing_dep.json` | ProofGraph | Claim depends on an ID that does not exist in the graph |
| `dag_duplicate_id.json` | ProofGraph | Two claims share the same `"id"` field |
| `evidence_wrong_size.json` | EvidenceDescriptor | `size` field does not match actual blob size |
| `evidence_wrong_digest.json` | EvidenceDescriptor | `digest` is well-formed sha256 but does not match blob content |
| `colluding_tamper.json` | ProofGraph | Weil colluding-tamper: claim evidence digest in graph differs from attestation's recorded digest |
| `attestation_forbidden_assurance.json` | Attestation | Uses `"ai-review"` assurance, which is forbidden by `policies/weil-release-v1.json` |
| `checker_path_only.json` | CheckerIdentity | `checker_digest` is empty — represents an unpinned checker |

## Large/Generated Fixtures

The following fixtures are NOT stored in this directory because they would bloat the
repository. They are generated in test code directly:

- **Deep nesting**: a Claim with 10000 entries in `depends_on` — tests resource limits
- **Large text**: a Claim with 1 MB of repeated characters in `statement.text` — tests size limits

## Policy Context

The `policies/weil-release-v1.json` file forbids `"ai-review"` and `"assumption"` assurances
and requires all 12 claims in the Weil theorem proof. These adversarial fixtures target that policy.

## Rule

No test may assert that loading any of these fixtures results in a passing/accepted outcome.
If a new test accidentally accepts one of these inputs, it is a security regression.
