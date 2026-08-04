# Checker Protocol

## Overview

Checkers are external processes that verify mathematical claims. They communicate
with the proofctl engine via a simple stdin/stdout JSON protocol. This document
defines the protocol version 1 interface.

The protocol is designed to be:
- **Deterministic**: the same inputs must always produce the same output.
- **Isolated**: checkers must not modify any input files or the CAS.
- **Fail-closed**: any ambiguous or missing output is treated as an error, not a pass.

## Invocation

The engine invokes a checker as a subprocess:

```
<checker-binary> [no arguments]
```

- Standard input carries a single `CheckerInput` JSON object.
- Standard output must carry a single `CheckerOutput` JSON object (on exit 0 or 1)
  or a single `CheckerError` JSON object (on exit 2 or 3).
- Standard error may contain diagnostic text and is logged by the engine; it
  does not affect the outcome.
- The checker must exit before the wall-clock timeout (default 5 minutes).

## Exit Codes

| Code | Meaning       | Expected stdout type |
|------|---------------|----------------------|
| 0    | Pass          | `CheckerOutput` with `outcome: "accepted"` |
| 1    | Fail          | `CheckerOutput` with `outcome: "rejected"` or `"disproved"` |
| 2    | Unavailable   | `CheckerError` with machine-readable `code` |
| 3    | Protocol error| `CheckerError` with machine-readable `code` |

Exit code 2 means the checker cannot currently run (e.g. a required tool is
missing, a service is unavailable). The engine will retry after a backoff.

Exit code 3 means the checker itself violated the protocol (e.g. produced
malformed JSON, wrote nothing to stdout, timed out). The engine records this
as `outcome: "error"` with `error_code: "PROTOCOL_ERROR"`.

**Any other exit code is treated as exit code 3.**

## CheckerInput (stdin)

```json
{
  "protocol_version": 1,
  "claim_id": "lem-d1-normalization",
  "statement_digest": "sha256:a1b2c3...",
  "statement_text": "The normalization factor N satisfies 0 < N <= 1.",
  "dependency_digests": {
    "def-frozen-model": "sha256:def000..."
  },
  "evidence": [
    {
      "media_type": "application/x-lean-proof-term",
      "digest": "sha256:fedcba...",
      "size": 204800,
      "local_path": "/tmp/proofctl-cas/sha256/fe/dcba..."
    }
  ],
  "policy_digest": "sha256:112233..."
}
```

Fields:
- `protocol_version`: Must be `1`. The checker must reject inputs with a different version.
- `claim_id`: The claim being verified.
- `statement_digest`: Content-addressed digest of the statement text.
- `statement_text`: The human-readable claim statement for reference.
- `dependency_digests`: Map from dependency claim ID to its statement digest.
  The checker must verify that its proof relies on the exact statements indicated.
- `evidence`: List of evidence blobs available for reading. `local_path` is a
  read-only path to the blob in the CAS. The checker must not modify this path.
- `policy_digest`: Digest of the policy file that governs this invocation.

## CheckerOutput (stdout)

```json
{
  "protocol_version": 1,
  "claim_id": "lem-d1-normalization",
  "outcome": "accepted",
  "assurance": "formal-kernel",
  "explanation": "Lean 4 kernel accepted the proof term without errors.",
  "resources": {
    "wall_millis": 12043,
    "cpu_millis": 11800,
    "mem_bytes": 536870912
  }
}
```

Fields:
- `protocol_version`: Must echo `CheckerInput.protocol_version`.
- `claim_id`: Must echo `CheckerInput.claim_id`.
- `outcome`: One of `accepted`, `rejected`, `disproved`, `error`.
  `disproved` is used when the checker produced a counterexample.
- `assurance`: The assurance type the checker asserts. Must be one of the types
  defined in docs/ASSURANCE_MODEL.md.
- `explanation` (optional): Human-readable explanation of the outcome.
- `error_code` (optional): Machine-readable code when `outcome` is `error`.
- `resources`: Resource consumption. All fields required.

## CheckerError (stdout, exit 2 or 3)

```json
{
  "protocol_version": 1,
  "claim_id": "lem-d1-normalization",
  "code": "LEAN_EXECUTABLE_NOT_FOUND",
  "message": "lean4 binary not found in PATH"
}
```

## Resource Limits

| Resource    | Default limit | Notes                                |
|-------------|--------------|--------------------------------------|
| Wall time   | 5 minutes    | Configurable per checker policy      |
| Memory      | 4 GiB        | Enforced by deployment (cgroups)     |
| Disk write  | 0 bytes      | Checkers must not write to disk      |
| Network     | None         | Release checkers must use `network: "none"` |

## Error Classification

| error_code                  | Meaning                                         |
|-----------------------------|-------------------------------------------------|
| `PROTOCOL_ERROR`            | Checker violated the stdin/stdout protocol      |
| `CHECKER_DIGEST_MISMATCH`   | Checker binary digest did not match declared    |
| `EVIDENCE_UNAVAILABLE`      | Required evidence blob not in CAS               |
| `DEPENDENCY_DIGEST_MISMATCH`| A dependency statement changed since attestation|
| `TIMEOUT`                   | Checker exceeded the wall-clock timeout         |
| `OUT_OF_MEMORY`             | Checker exceeded the memory limit               |
| `INTERNAL_ERROR`            | Unclassified checker-internal error             |

## Protocol Versioning

The protocol version is a positive **integer**. The current version is `1`.

> **Important:** `protocol_version` must be an integer literal (e.g. `1`), never
> a string (e.g. `"1"`). Checkers that output a string will receive a JSON decode
> error from the engine.

- A checker must reject any `CheckerInput` whose `protocol_version` differs from
  the version it implements, by exiting 3 with `code: "UNSUPPORTED_PROTOCOL_VERSION"`.
- The engine must reject any `CheckerOutput` or `CheckerError` whose
  `protocol_version` differs from the input's.
- Protocol version increments are breaking changes. Checkers declaring
  `protocol_version: 1` in their `CheckerIdentity` will never receive a v2 input.

## Replay Mode

proofctl records how a certificate was verified in the `replay_mode` field of each
attestation:

| Value | Set by | Meaning |
|---|---|---|
| `"from_scratch"` | `proofctl replay` | Generator re-run; output digest compared against pinned evidence |
| `"self_consistency"` | `proofctl check` | Checker ran against already-imported CAS evidence; no generator re-run |

Attestations written before this field was introduced have an empty `replay_mode`
and are treated as legacy (exempt from `required_replay_mode` policy enforcement).

Policies can require a specific replay depth:

```json
"required_replay_mode": "from_scratch"
```

This activates release condition C08. Any attestation with a non-empty `replay_mode`
that does not match will block release.
