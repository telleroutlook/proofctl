# Lean 4 Domain — proofctl Protocol Specification

## Overview

The `lean` domain integrates [Lean 4](https://leanprover.github.io/) with proofctl.
Lean 4 proofs are verified using `lake build` (the Lake build system) and optionally
re-checked with `lean4checker` for independent kernel verification. The bridge
captures tool versions and the Mathlib commit hash from `lake-manifest.json`.

## Claim ID convention

Lean 4 theorem names are mapped to claim IDs using the prefix `thm-` and replacing
dots with hyphens:

```
MyProof.myTheorem       →  thm-MyProof-myTheorem
Mathlib.Analysis.foo    →  thm-Mathlib-Analysis-foo
```

The `-- claim: <id>` annotation in a `.lean` file explicitly declares the mapping:

```lean
-- claim: thm-MyProof-myTheorem
theorem myTheorem : True := trivial
```

## Checker invocation

```
adapters/lean/bridge.py <cert-file>
```

Where `<cert-file>` is a JSON file containing:

```json
{
  "lean_file": "MyProof.lean",
  "theorem":   "MyProof.myTheorem",
  "lake_root": "."
}
```

The bridge runs:

```sh
lake build
lean --version          # to capture lean_version
cat lake-manifest.json  # to extract mathlib_commit
```

## Bridge output (stdout)

On success (exit 0):

```json
{
  "protocol_version": 1,
  "claim_id": "",
  "outcome": "accepted",
  "assurance": "formal-kernel",
  "metadata": {
    "lean_file": "MyProof.lean",
    "theorem": "MyProof.myTheorem"
  },
  "toolchain": {
    "lean_version": "4.14.0",
    "mathlib_commit": "a3f1b2c",
    "lake_version": "4.14.0"
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
    "theorem": "MyProof.myTheorem",
    "error": "lake build failed: ..."
  }
}
```

## graph.json structure

Each theorem gets one claim. Dependencies follow the `-- claim: <id>` annotations
and the `import` graph (inferred by `adapter.go`).

## BatchGroup usage

Lean's `lake build` verifies the entire project at once. All claims in a Lean
project share `batch_group: "lean-env"` so proofctl calls the checker once
and fans out the results using M13's `BatchRunner`:

```json
{
  "id": "thm-MyProof-myTheorem",
  "batch_group": "lean-env",
  "checker_policy": "lean-checker-v1"
}
```

## Policy

```json
{
  "allowed_assurances": ["formal-kernel"],
  "required_metadata_keys": [],
  "required_signed_attestations": false
}
```

## CompileGraph (adapter.go)

Scans `.lean` files for `-- claim: <id>` annotations and infers dependency order
from `import` statements. Returns a `*ir.ProofGraph` with `batch_group: "lean-env"`
on all claims.
