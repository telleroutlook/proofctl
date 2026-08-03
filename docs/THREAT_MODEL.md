# Threat Model — proofctl Proof Graph Engine

## Overview

This document describes the threat model for the proofctl Proof Graph Engine.
The engine verifies mathematical claims by orchestrating pinned checkers against
content-addressed evidence and recording attestations. The release gate is
fail-closed: the certified radius remains null unless every required claim is
accepted under an allowed assurance type.

## Scope

This threat model covers:
- The proofctl binary and its internal packages
- The content-addressed store (CAS)
- Checker invocation and the stdin/stdout protocol
- Attestation records and the STATUS.json release artifact
- The policy file and claim graph source

## Attacker Capabilities

The threat model assumes an attacker who can:

1. **Modify certificates and attestation files** — read and write files in the
   output and attestation directories, including STATUS.json.
2. **Substitute checker binaries** — replace a checker binary with a malicious
   version that always exits 0.
3. **Modify configuration and policy files** — edit the release policy JSON to
   remove required claims or permit forbidden assurance types.
4. **Poison the content-addressed cache** — write crafted blobs to the CAS
   directory, or replace an existing blob with a different payload under the
   same path.
5. **Modify documentation and source files** — edit claim source files, evidence
   files, or this threat model document itself.
6. **Control the runtime environment** — set environment variables, PATH, and
   working directory for the proofctl process.
7. **Collude with one or more (but not all) independent reviewers** — partial
   corruption of independent review evidence.
8. **Conduct resource attacks** — consume excessive CPU, memory, or disk to cause
   checkers to time out or produce error outcomes.
9. **Introduce state drift** — modify input files between the freshness snapshot
   recorded at the start of a checker run and the end of the run.

## Trust Boundaries

```
  ┌─────────────────────────────────────────────────────┐
  │  proofctl process                                   │
  │                                                     │
  │  ┌──────────┐    ┌─────────┐    ┌───────────────┐  │
  │  │ Policy   │    │  DAG    │    │  Attestation  │  │
  │  │ (pinned) │    │ (built  │    │  (self-digest)│  │
  │  └──────────┘    │ from    │    └───────────────┘  │
  │                  │ source) │                        │
  │  ┌──────────┐    └─────────┘    ┌───────────────┐  │
  │  │  CAS     │                   │  Release Gate │  │
  │  │ (sha256) │                   │  (fail-closed)│  │
  │  └──────────┘                   └───────────────┘  │
  └──────────────────────┬──────────────────────────────┘
                         │  stdin/stdout protocol
                    ┌────┴────┐
                    │ Checker │  (external process)
                    │ process │
                    └─────────┘
```

**Trusted:** The proofctl binary itself (assumed unmodified).
**Partially trusted:** Checker binaries (pinned by digest, but run as subprocesses).
**Untrusted:** All file-system content (CAS blobs, attestation files, policy
files, source files, STATUS.json).

## Attack Vectors and Mitigations

### 1. Certificate / Attestation Swap

**Attack:** An attacker replaces an attestation file with a fabricated one
claiming a claim is accepted when it was not.

**Mitigation:** Every attestation carries a `self_digest` field (SHA256 over
the attestation payload excluding `self_digest`). The engine recomputes this
digest on load and rejects any attestation whose `self_digest` does not match.
The `statement_digest` and `dependency_digests` fields bind the attestation to
the exact claim text and dependency graph at the time of verification.

**Residual risk:** An attacker who can both replace the attestation file and
also recompute a valid `self_digest` over a forged payload can bypass this
check. Cryptographic signing of attestations (out of scope for v1) would
eliminate this risk.

### 2. Checker Substitution

**Attack:** An attacker replaces a checker binary with a malicious version that
always exits 0 and produces a forged `CheckerOutput`.

**Mitigation:** Every checker is identified by a `CheckerIdentity` that includes
`checker_digest` (SHA256 of the binary or OCI image). The engine verifies the
binary digest before invocation. If the digest does not match, the check is
aborted with `error_code=CHECKER_DIGEST_MISMATCH`.

**Residual risk (v1 — addressed):** Digest verification for native binaries is
now implemented in the `NativeRunner` (`verifyBinaryDigest`). The runner
rejects any binary whose SHA256 does not match `CheckerIdentity.CheckerDigest`
before execution. The all-zeros digest is accepted as a development placeholder
only when the runner is already operating in the `development-unisolated`
assurance mode.

**Residual risk (production):** For production release attestations, the
`NativeRunner` must not be used. Formal release requires an OCI-isolated runner
with image digest pinned at the registry level. The `RuntimeAssuranceDevelopmentUnisolated`
assurance type is permanently excluded from the allowed assurance list for
release.

### 3. Cache Poisoning

**Attack:** An attacker writes a crafted blob to the CAS directory under a
path that would be read during evidence verification, causing the checker to
operate on tampered evidence.

**Mitigation:** The `cas.Verify` function checks both the byte size and the
SHA256 digest of every blob before it is passed to a checker. A blob with the
correct path but wrong content will fail the digest check and cause the
invocation to be aborted.

**Residual risk:** If an attacker can compute a SHA256 collision, the mitigation
fails. SHA256 collisions are not considered feasible at this time.

### 4. Policy Tampering

**Attack:** An attacker edits the release policy file to remove required claims
from `required_claims` or to move a forbidden assurance type (e.g. `ai-review`)
to `allowed_assurances`.

**Mitigation:** The policy file digest (`policy_digest`) is recorded in every
attestation's cache key via `checker.CacheKey`. A policy change invalidates all
cached checker results, forcing re-verification under the new policy. However,
the engine does not currently pin or sign the policy file itself.

**Residual risk (v1):** There is no cryptographic binding between the policy
file on disk and the policy digest recorded in attestations. An attacker who
can modify both the policy file and the attestations can bypass this control.
Policy signing is planned for v2.

### 5. Colluding Multi-Party Tampering

**Attack:** Multiple parties cooperate to modify both the claim source, the
evidence blobs, and the attestations in a consistent way so that all digests
still match the forged content.

**Mitigation:** The engine makes consistent forgery difficult by requiring
content-addressed evidence, statement digests, and attestation self-digests to
all be mutually consistent. However, the engine cannot detect a coordinated
forgery in which all artifacts are replaced consistently and all digests are
recomputed.

**Non-mitigation (v1):** Defense against a fully coordinated forgery requires
external signing by an independent party (e.g. a hardware security module or
a transparency log). This is out of scope for v1.

### 6. Resource Exhaustion

**Attack:** An attacker provides evidence blobs or claim statements that cause
checkers to consume excessive CPU or memory, eventually timing out and producing
error attestations that block release.

**Mitigation:** The `NativeRunner` enforces a configurable wall-clock timeout
(default 5 minutes) and the `MaxMemBytes` constant documents the intended memory
limit. Platform-level enforcement (cgroups, `ulimit`) is the responsibility of
the deployment environment.

### 7. State Drift

**Attack:** An attacker modifies an input file (evidence blob, claim source)
between the freshness snapshot taken at the start of a checker invocation and
the end. This could cause the checker to verify a different artifact than the
one recorded in the attestation.

**Mitigation:** The `freshness.Snapshot` and `freshness.Verify` functions record
SHA256 digests of all input paths before and after invocation. If any path
changes, the attestation is marked invalid. The `start_freshness` and
`end_freshness` fields in the attestation record the snapshot digests.

### 8. Source File Modification

**Attack:** An attacker modifies a claim's source text after an attestation has
been issued, changing the meaning of the claim while leaving the attestation in
place.

**Mitigation:** The `statement_digest` in each attestation is a SHA256 of the
claim text at the time of verification. If the source text changes, the digest
will not match, and the attestation will be rejected as stale.

## Responsibility Boundary: proofctl vs. External Checkers

proofctl is an **orchestration and attestation engine**. It is not a mathematical
proof checker. The following table makes the division explicit so that readers do
not infer security guarantees that proofctl cannot provide.

| Concern | Responsible party | How |
|---|---|---|
| Path traversal in digest or claim ID | **proofctl** | `parseDigest` enforces `^[0-9a-f]{64}$`; `ValidateClaimID` enforces `^[a-zA-Z0-9_.-]+$`, no leading `.`, no `..` |
| Evidence content integrity | **proofctl** | `cas.Verify` checks SHA256 and byte size before passing to any checker |
| Attestation self-consistency | **proofctl** | `self_digest` is recomputed on load; mismatch → rejection |
| Release gate (fail-closed) | **proofctl** | Policy-driven, deterministic, all conditions must pass |
| Freshness / TOCTOU | **proofctl** | `freshness.Snapshot` + `Verify` before and after every checker run |
| Checker binary identity | **proofctl** | `verifyBinaryDigest` checks `CheckerIdentity.CheckerDigest` before exec |
| **κ (kappa) bound correctness** | **External Weil checker** | The Weil checker (Python + FLINT/Arb) computes and verifies the κ bound; proofctl only records the checker's `accepted`/`rejected` attestation |
| **C_a colluding-forgery detection** | **External Weil checker** | Algebraic consistency of the C_a coefficient set is a mathematical invariant that only the Weil checker can evaluate; proofctl verifies the evidence digest but not the algebraic content |
| **Numerical precision of Weil sums** | **External Weil checker** | Interval arithmetic, L-D-L^T stability, log-moment estimates — all computed by the checker; proofctl pins the checker binary by digest to ensure the same code runs every time |
| **Formal kernel proofs (Lean 4)** | **External Lean kernel** | Kernel-level proof checking is delegated to the Lean 4 type checker; proofctl pins the Lean binary digest and records the attestation |

### What this means for the security model

An attacker who can corrupt the **output** of an external checker (its
`CheckerOutput` JSON) without changing the checker binary digest can inject a
false `accepted` outcome. This is mitigated by binary digest pinning
(`verifyBinaryDigest`) and, for production releases, by OCI-isolated execution
with an immutable image digest. It is **not** mitigated by proofctl alone.

An attacker who breaks the **mathematics** (finds a counterexample to a Weil
claim) is outside the scope of this threat model. proofctl's job is to ensure
that the checker which evaluated the claim is exactly the pinned version, that
the evidence it saw is the pinned content, and that the recorded attestation has
not been tampered with after the fact.

## Explicit Non-Mitigations in v1

The following attack vectors are **not mitigated** in v1 and are accepted risks:

1. **Compromise of the proofctl binary itself** — if the binary is replaced with
   a malicious version, no in-process defense is possible.
2. **Side-channel attacks** on checker invocations — timing or cache-based
   inference of proof content is not considered.
3. **Denial of service via disk exhaustion** — the CAS does not enforce storage
   quotas.
4. **Replay of old valid attestations against new claim versions** — partial
   mitigation via `statement_digest`, but no timestamp or sequence number.
5. **Checker source code analysis** — the engine pins checker binaries by digest
   but does not audit checker source code for correctness.
6. **Hardware-level attacks** — row hammer, speculative execution side channels,
   and similar hardware attacks are out of scope.
7. **Policy signing** — the policy file is not cryptographically signed in v1.

## Assumptions

- The host operating system provides correct filesystem semantics (atomic rename,
  fsync durability).
- SHA256 is collision-resistant for the threat model's lifetime.
- The Go standard library's `crypto/sha256` implementation is correct.
- The attacker cannot modify the proofctl binary in memory during execution.
