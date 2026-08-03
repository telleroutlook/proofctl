# Assurance Model

## Overview

The proofctl assurance model explicitly tracks the epistemic category of each
verification result. Assurance types are never collapsed into a single numeric
score. A claim may require multiple assurance types, and the release policy
independently governs which types are allowed and which are forbidden.

The guiding principle is: **different assurance types answer different questions**
and are not interchangeable.

## Assurance Types

### `formal-kernel`

A verified proof term was accepted by a formally specified, mechanically checked
kernel (e.g. the Lean 4 kernel, Coq's kernel). This is the highest assurance
type. The checker must be a pinned, content-addressed kernel binary. No human
judgment is involved in the accept/reject decision.

**Suitable for:** Main theorems, lemmas that are prerequisites for release.
**Not suitable for:** Claims about external data quality or experimental results.

### `deterministic-cap`

A computation was verified to be fully deterministic and capability-bounded.
The checker runs the computation twice in isolation and confirms bit-for-bit
identical results. Network access must be `none`.

**Suitable for:** Numerical computations with specified rounding, matrix
factorizations with fixed algorithms.
**Not suitable for:** Any computation involving randomness or external state.

### `exact-replay`

An exact byte-for-byte replay of a previously recorded computation was
verified. The checker compares the output to a pinned recording stored as
evidence in the CAS.

**Suitable for:** Confirming that a computation has not changed since a
reference run was recorded.
**Not suitable for:** First-time verification (requires a prior recording).

### `reproducible-computation`

An independent re-execution of a computation produced results within a
specified tolerance of the original. Unlike `exact-replay`, small numerical
differences are permitted if within the documented tolerance envelope.

**Suitable for:** Floating-point computations where exact replay is not
achievable across platforms.
**Not suitable for:** Proofs that require exact bitwise reproducibility.

### `independent-review`

A qualified human reviewer (independent of the original author) reviewed the
claim and evidence and produced a signed review record. The checker verifies
the reviewer's signature and checks the reviewer is not the claim author.

**Suitable for:** Claims that cannot be mechanically verified, auxiliary
assumptions, documentation correctness.
**Not suitable for:** Main theorem claims in a release (should use `formal-kernel`).

### `ai-review`

An AI system reviewed the claim. This type is **always forbidden** in release
policies for main theorem claims. It may be used for development-phase triage
and intermediate review, but must never be the sole or primary assurance for
a released claim.

**Forbidden by default in:** `weil-release-v1.json` and all main theorem policies.
**Permitted in:** Development-mode policies only.

### `assumption`

The claim is accepted as an axiom or assumption without verification. This type
is **always forbidden** in release policies for provable claims. Its presence
in an attestation for a lemma or theorem is a policy violation.

**Forbidden by default in:** `weil-release-v1.json` and all main theorem policies.
**Permitted in:** Explicit axiom claims (`kind: "axiom"`), subject to reviewer sign-off.

## Release Policy Format

A release policy is a JSON file with the following structure:

```json
{
  "version": "1",
  "target": "thm-main-radius-030",
  "allowed_assurances": [
    "formal-kernel", "deterministic-cap", "exact-replay",
    "reproducible-computation", "independent-review"
  ],
  "forbidden_assurances": ["ai-review", "assumption"],
  "required_claims": [
    "def-frozen-model",
    "lem-d1-normalization",
    "thm-main-radius-030"
  ]
}
```

Fields:
- `version`: Policy file version (string). Changing this invalidates cached results.
- `target`: The root claim that must be accepted for the release to pass.
- `allowed_assurances`: If non-empty, only these assurance types are permitted.
  Any attestation using a type not in this list blocks release.
- `forbidden_assurances`: These assurance types are never permitted, regardless
  of `allowed_assurances`. Checked first.
- `required_claims`: Every claim in this list must have an accepted attestation.

## Why No Single Score

A single score (e.g. "confidence: 0.95") would:

1. Allow trading off assurance types — e.g. replacing one `formal-kernel`
   attestation with many `ai-review` attestations to reach the same score.
2. Obscure the epistemic basis of the verification — a score of 0.9 could mean
   "almost formal" or "many independent reviews" and these have very different
   implications.
3. Make policy violations harder to detect — a policy violation would reduce
   the score but might not drop below the threshold.

The proofctl model instead maintains a strict per-claim assurance type that is
checked independently against the policy. Two claims at the same assurance level
are comparable; two claims at different levels are not substitutable.

## Default Forbidden Types

The following assurance types are forbidden by default in all release policies
for main theorem claims:

| Type         | Reason for default prohibition                        |
|--------------|-------------------------------------------------------|
| `ai-review`  | AI review does not constitute mathematical proof.     |
| `assumption` | Unverified assumptions invalidate downstream proofs.  |

These defaults can only be overridden by an explicit policy file that lists
the type in `allowed_assurances` and removes it from `forbidden_assurances`,
subject to human sign-off documented in the policy's commit history.
