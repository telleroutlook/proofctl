# ProofGraph IR — Intermediate Representation

## Overview

The ProofGraph Intermediate Representation (IR) is the canonical data format
used internally by proofctl to represent a mathematical proof graph. All source
formats (JSON, Weil Phase B, Lean 4, QMD) are compiled to ProofGraph IR before
any verification or analysis is performed.

The IR is defined in `internal/ir/types.go` and serialized as JSON. All JSON
decoding uses `DisallowUnknownFields()` to reject forward-compatibility hazards.

## Top-Level Type: ProofGraph

A `ProofGraph` is the root container. It holds claims, checker identities, and
evidence descriptors.

```json
{
  "claims": [...],
  "checkers": [...],
  "evidence": [...]
}
```

Fields:
- `claims`: Ordered list of `Claim` objects. Order does not imply topology;
  the DAG is derived from `depends_on` references.
- `checkers`: List of `CheckerIdentity` objects available in this graph.
- `evidence`: List of `EvidenceDescriptor` objects referenced by claims.

## Claim

A `Claim` is a node in the proof DAG. It carries a statement, dependency edges,
assurance requirements, evidence references, and a checker policy reference.

```json
{
  "id": "lem-d1-normalization",
  "kind": "lemma",
  "statement": {
    "text": "The normalization factor N satisfies 0 < N <= 1 for all valid inputs.",
    "digest": "sha256:a1b2c3d4e5f6..."
  },
  "depends_on": ["def-frozen-model"],
  "required_assurance": ["formal-kernel", "deterministic-cap"],
  "evidence": ["sha256:deadbeef1234..."],
  "checker_policy": "policies/weil-release-v1.json"
}
```

Fields:
- `id`: Unique string identifier within the proof graph. Must be non-empty.
- `kind`: One of `theorem`, `lemma`, `definition`, `axiom`, `conjecture`,
  `assumption`.
- `statement`: A `Statement` object containing the human-readable text and its
  content-addressed digest.
- `depends_on`: List of claim IDs that must be accepted before this claim can
  be verified. Forms the DAG edges.
- `required_assurance`: List of assurance types that must all be present in the
  final attestation for this claim to be considered accepted.
- `evidence`: List of `sha256:<hex>` digest references to evidence blobs in the
  CAS. The blobs are verified before being passed to the checker.
- `checker_policy`: Path or ID of the policy file governing checker selection
  and resource limits for this claim.

## Statement

A `Statement` binds a human-readable text to a content-addressed digest.
The digest is `sha256:` followed by the lowercase hex SHA256 of the UTF-8
encoded text.

```json
{
  "text": "For all x in the domain, f(x) >= 0.",
  "digest": "sha256:7f83b1657ff1fc53b92dc18148a1d6..."
}
```

The engine recomputes and verifies the digest on load. If `text` and `digest`
are inconsistent, the claim is rejected.

## EvidenceDescriptor

An `EvidenceDescriptor` identifies a piece of evidence by its content address.
It is the stable reference to a blob in the CAS.

```json
{
  "media_type": "application/x-lean-proof-term",
  "digest": "sha256:fedcba9876543210...",
  "size": 204800,
  "path_hint": "proofs/lem-d1-norm.lp"
}
```

Fields:
- `media_type`: MIME type of the blob. Checkers use this to determine how to
  interpret the evidence.
- `digest`: SHA256 digest of the blob. The CAS verifies this before returning
  the blob to any caller.
- `size`: Byte size of the blob. The CAS checks this before computing the full
  digest, providing a fast pre-check.
- `path_hint` (optional): A non-authoritative hint for humans or tooling to
  locate the original file. Never trusted by the engine.

## CheckerIdentity

A `CheckerIdentity` pins a checker to an exact binary or image digest and
runtime environment. Two invocations with the same `CheckerIdentity` and the
same inputs must produce the same output for the assurance claim to hold.

```json
{
  "id": "lean4-kernel-checker",
  "protocol_version": 1,
  "checker_digest": "sha256:aabbccddeeff...",
  "schema_digest": "sha256:11223344556677...",
  "runtime": {
    "kind": "oci",
    "digest": "sha256:99aabbccddeeff..."
  },
  "network": "none"
}
```

Fields:
- `id`: Human-readable name for the checker.
- `protocol_version`: Must match `pkg/protocol.ProtocolVersion`.
- `checker_digest`: SHA256 of the checker binary or OCI image manifest.
- `schema_digest`: SHA256 of the JSON schema governing `CheckerInput` and
  `CheckerOutput` for this checker version.
- `runtime.kind`: One of `oci`, `native`, `wasi`.
- `runtime.digest`: For `oci` and `wasi`, the digest of the runtime image.
  Omitted for `native`.
- `network`: One of `none`, `loopback`, `unrestricted`. Release policies
  require `none` for all checkers verifying main theorem claims.

## Attestation

An `Attestation` records a single completed checker invocation. It binds the
outcome to the exact claim, dependencies, evidence, and checker that produced
it.

```json
{
  "claim_id": "lem-d1-normalization",
  "statement_digest": "sha256:a1b2c3d4e5f6...",
  "dependency_digests": ["sha256:def000111222..."],
  "evidence": [
    {
      "media_type": "application/x-lean-proof-term",
      "digest": "sha256:fedcba9876543210...",
      "size": 204800
    }
  ],
  "checker": { ... },
  "outcome": "accepted",
  "assurance": "formal-kernel",
  "resources": {
    "wall_millis": 12043,
    "cpu_millis": 11800,
    "mem_bytes": 536870912
  },
  "start_freshness": "sha256:aaa111...",
  "end_freshness": "sha256:aaa111...",
  "self_digest": "sha256:bbb222..."
}
```

Fields:
- `claim_id`: The claim this attestation covers.
- `statement_digest`: SHA256 of the claim statement at time of attestation.
  Used to detect stale attestations if the claim text changes.
- `dependency_digests`: Statement digests of all transitive dependencies,
  in topological order. Any dependency change invalidates this attestation.
- `evidence`: The exact evidence descriptors passed to the checker.
- `checker`: The `CheckerIdentity` that produced this attestation.
- `outcome`: One of `open`, `blocked`, `accepted`, `rejected`, `error`,
  `disproved`, `abandoned`.
- `assurance`: The assurance type the checker asserts.
- `error_code` (optional): Machine-readable code when `outcome` is `error`.
- `block_reason` (optional): Human-readable reason when `outcome` is `blocked`.
- `resources`: CPU, wall time, and memory consumed during the invocation.
- `start_freshness` / `end_freshness`: Freshness snapshot digests taken before
  and after the invocation. If they differ, input drift occurred.
- `self_digest`: SHA256 of the attestation record excluding this field.

## ResourceStats

```json
{
  "wall_millis": 12043,
  "cpu_millis": 11800,
  "mem_bytes": 536870912
}
```

All fields are non-negative integers. `mem_bytes` is peak resident set size.

## Status Values

| Status       | Meaning                                                  |
|-------------|----------------------------------------------------------|
| `open`      | No attestation yet; not blocked by dependencies.         |
| `blocked`   | A transitive dependency is rejected, disproved, or error.|
| `accepted`  | Checker returned accepted outcome.                       |
| `rejected`  | Checker returned rejected outcome.                       |
| `error`     | Checker invocation encountered an unrecoverable error.   |
| `disproved` | Checker produced a counterexample.                       |
| `abandoned` | Claim was explicitly abandoned by the proof author.      |
