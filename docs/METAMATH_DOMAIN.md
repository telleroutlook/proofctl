# Metamath Domain — proofctl Protocol Specification

## Overview

The `metamath` domain integrates the [Metamath](http://us.metamath.org/) proof
verification system with proofctl. Metamath verifies mathematical proofs stored
in `.mm` files using a small, auditable kernel. Each theorem is verified
independently, which maps cleanly to proofctl's single-claim-per-checker model.

## Claim ID convention

Metamath theorem labels map to claim IDs using the prefix `thm-`:

```
mp   →  thm-mp
ax-1  →  thm-ax-1
sqrt2  →  thm-sqrt2
```

The label must contain only characters allowed by `ir.ValidateClaimID`
(`[a-zA-Z0-9_.-]+`). Labels with special characters (e.g. `*`, `=`) should
be escaped by replacing them with `-` and noting the mapping in a comment.

## Checker invocation

```
adapters/metamath/bridge.py <cert-file>
```

Where `<cert-file>` is a JSON file containing:

```json
{
  "mm_file": "path/to/proof.mm",
  "theorem": "mp"
}
```

The bridge runs:

```sh
metamath 'read "proof.mm"' 'verify proof *' 'exit'
```

and checks whether the theorem label appears in the verified output.

## Bridge output (stdout)

On success (exit 0):

```json
{
  "protocol_version": 1,
  "claim_id": "",
  "outcome": "accepted",
  "assurance": "formal-kernel",
  "metadata": {
    "metamath_version": "0.198",
    "theorem": "mp",
    "mm_file": "path/to/proof.mm"
  }
}
```

On failure (exit 1):

```json
{
  "protocol_version": 1,
  "claim_id": "",
  "outcome": "rejected",
  "assurance": "formal-kernel",
  "metadata": {
    "theorem": "mp",
    "error": "theorem not found or proof failed"
  }
}
```

## graph.json structure

A Metamath proof graph typically has two claims:

```json
{
  "claims": [
    {
      "id": "thm-lem",
      "kind": "lemma",
      "statement": {"text": "Lemma: ...", "digest": "sha256:0000..."},
      "depends_on": [],
      "checker_policy": "metamath-checker-v1"
    },
    {
      "id": "thm-main",
      "kind": "theorem",
      "statement": {"text": "Main theorem: ...", "digest": "sha256:0000..."},
      "depends_on": ["thm-lem"],
      "checker_policy": "metamath-checker-v1"
    }
  ]
}
```

## Policy

```json
{
  "allowed_assurances": ["formal-kernel"],
  "forbidden_assurances": ["assumption", "ai-review"],
  "required_metadata_keys": ["metamath_version", "theorem"]
}
```

## CompileGraph (adapter.go)

`adapters/metamath/adapter.go` implements `CompileGraph(src []byte)` which:

1. Scans the `.mm` source for `$p` statements (provable assertions)
2. Extracts the theorem label from each `$p ... $=` block
3. Infers dependency order from `$e` (hypothesis) references
4. Returns a `*ir.ProofGraph` with one claim per theorem

## No BatchGroup

Each Metamath theorem is verified independently — no `batch_group` needed.
The `metamath verify proof *` command verifies all proofs at once, but
proofctl invokes bridge.py once per claim (passing the specific theorem label),
so each claim gets its own attestation.
