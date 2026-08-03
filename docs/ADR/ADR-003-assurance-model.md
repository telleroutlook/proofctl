# ADR-003: Assurance Types as Distinct Categories, Not a Score

**Date:** 2026-08-03  
**Status:** Accepted  
**Deciders:** proofctl core team

---

## Context

Mathematical certification requires knowing **how** a claim was verified, not just
whether it passed some threshold. A single numeric trust score (e.g., 0–100%) fails
for the following reasons:

1. **Incomparable methods**: a deterministic computation at 90% and a formal kernel
   proof at 50% cannot be meaningfully compared on a single scale.
2. **Score inflation**: under pressure, reviewers may round up marginal results to
   cross an arbitrary threshold.
3. **Aggregation fallacy**: averaging scores across a chain of claims hides that any
   single failed link is sufficient to block the theorem.
4. **Audit trail**: a score carries no information about what was actually done.
   An attestation with a specific assurance type implies a specific verification
   methodology that can be independently audited.

The release policy for `thm-main-radius-030` requires that specific claims use
specific methods — for example, `lem-d4-kernel-bound` requires `formal-kernel`,
not just "high confidence." A score-based system cannot enforce this distinction.

---

## Decision

The ProofGraph Engine uses **7 discrete assurance types**, each representing a
distinct epistemic category with a specific implied methodology:

| Assurance Type             | Meaning                                                  |
|----------------------------|----------------------------------------------------------|
| `formal-kernel`            | Verified by a formal proof assistant kernel (e.g., Lean 4) |
| `deterministic-cap`        | Verified by a deterministic, capability-limited program  |
| `exact-replay`             | Verified by exact byte-for-byte replay of a recorded run |
| `reproducible-computation` | Verified by reproducing the computation from raw inputs  |
| `independent-review`       | Reviewed by a human expert independent of the original proof |
| `ai-review`                | Reviewed by an AI system (informational only)            |
| `assumption`               | Explicitly marked as an unverified assumption            |

The release policy for each theorem explicitly lists:

- `allowed_assurances`: the set of assurance types permitted for any attestation
  in the transitive closure.
- `forbidden_assurances`: assurance types that, if found in any attestation, block
  release regardless of outcome.

For `thm-main-radius-030`:
- `ai-review` and `assumption` are in `forbidden_assurances`.
- `shadow-review` (used by the Weil shadow adapter) is also forbidden.
- `formal-kernel` is required for the main theorem and for key lemmas (D1–D5, D8, D12–D16).

There is no mechanism to convert one assurance type to another, to "upgrade"
an `ai-review` result to `formal-kernel`, or to aggregate scores across types.

---

## Consequences

- An `ai-review` attestation **can never satisfy** the `formal-kernel` requirement
  for the main radius theorem. There is no workaround.
- An `assumption` attestation can never be used to satisfy any formal release
  requirement; it must be replaced with a real attestation before release.
- The release gate fails closed: if an attestation's assurance type is missing
  from the allowed list or present in the forbidden list, the gate blocks.
- Adding a new assurance type requires updating the policy schema, the allowed
  list in the relevant policy files, and this ADR.
- Score inflation is structurally impossible: there is no numeric score to inflate.
  A claim either has the required assurance type or it does not.
- The 7 types map directly to real verification methodologies. If a new methodology
  is developed (e.g., a new proof assistant), it gets a new distinct assurance type —
  not a score adjustment to an existing one.
