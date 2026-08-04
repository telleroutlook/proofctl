# Minimal Demo — Parity Arithmetic

This self-contained example walks through the full proofctl workflow:
**init → compile → check → release** using a toy proof about parity arithmetic.

No external checker is needed. `checker/check.sh` is a shell script that always
returns `accepted` — it plays the role a real SAT solver or interval-arithmetic
checker would fill in a production proof.

> **Note on `replay` vs `check`:** `proofctl replay` re-runs the generator from
> scratch and compares the output digest. It does **not** parse the checker's JSON
> output, so attestations written by `replay` carry no checker metadata.
> If your policy uses `required_metadata_keys`, use `proofctl check` instead —
> it invokes the checker against already-imported CAS evidence and records all
> metadata the checker outputs. This demo uses `check` so that `checker_name`
> and other keys from `check.sh` are available if you add them to the policy.

## Prerequisites

```sh
go install github.com/telleroutlook/proofctl/cmd/proofctl@latest
# or build from source:
go build -o proofctl ./cmd/proofctl && export PATH=$PWD:$PATH
```

## Run the demo

All commands are run from this directory (`examples/minimal/`).

### 1. Initialize the project

```sh
proofctl init --policy policies/minimal-v1.json
```

Creates `.proofctl/config.json`.

### 2. Compile the graph

```sh
proofctl compile --fix-digests graph.json
```

Reads `graph.json`, fills in the zero statement digests, and writes
`.proofctl/graph.json`.

### 3. Check status (all open)

```sh
proofctl status
```

All three claims are `open` — no attestations yet.

### 4. Import certificates into CAS and check each claim

`proofctl check` runs the checker against evidence already in the CAS and records
the attestation, including all metadata the checker outputs.

```sh
# Create a dummy certificate file for each claim and import it.
echo '{"result":"even+even=even"}' > /tmp/cert-even-sum.json
echo '{"result":"odd+even=odd"}'   > /tmp/cert-odd-plus-even.json
echo '{"result":"parity ok"}'      > /tmp/cert-parity-main.json

proofctl cas import /tmp/cert-even-sum.json
proofctl cas import /tmp/cert-odd-plus-even.json
proofctl cas import /tmp/cert-parity-main.json

# Run the checker for each claim (BRIDGE_CHECKER points to check.sh).
BRIDGE_CHECKER="sh checker/check.sh" proofctl check @lem-even-sum
BRIDGE_CHECKER="sh checker/check.sh" proofctl check @lem-odd-plus-even
BRIDGE_CHECKER="sh checker/check.sh" proofctl check @thm-parity-main
```

### 5. Check status (all accepted)

```sh
proofctl status
```

All three claims should now be `accepted`.

### 6. Release

```sh
proofctl release
```

Writes `.proofctl/STATUS.json` with `"released": true`.

```sh
cat .proofctl/STATUS.json
```

## What this demonstrates

| Step | proofctl concept |
|---|---|
| `init` | Project root + `.proofctl/config.json` |
| `compile --fix-digests` | Statement digest auto-fill; IR compilation |
| `cas import` | Import evidence blob into content-addressed storage |
| `check` | Checker invocation; attestation write with full metadata |
| `status` | DAG-aware status propagation |
| `release` | Fail-closed gate; C01–C04 universal conditions |

## Using `replay` instead of `check`

If you want to re-run certificate generation from scratch and compare digests,
use `proofctl replay`. Note that `replay` does not parse the checker's JSON output,
so `checker_name` and other metadata keys will **not** appear in the attestation.
This demo's policy deliberately omits `required_metadata_keys` so both workflows
succeed. Production policies that require metadata keys (e.g. `cap_format_version`)
must use `check` or `proofctl check --evidence`.

```sh
# Single-evidence replay (after importing the cert):
BRIDGE_CHECKER="sh checker/check.sh" \
proofctl replay \
  --claim lem-even-sum \
  --evidence sha256:$(sha256sum /tmp/cert-even-sum.json | awk '{print $1}') \
  --generator "cp /tmp/cert-even-sum.json {cert}"
```

## Adapting for a real proof

Replace `checker/check.sh` with your domain checker (SAT solver, interval
arithmetic library, formal-kernel verifier, etc.). The checker must:

1. Accept a certificate file path as `$1`
2. Print a JSON object to stdout matching the [checker protocol](../../pkg/protocol/)
   — `protocol_version` must be an **integer** (not a string)
3. Exit `0` on success, non-zero on failure

See `adapters/cap/bridge.py` for a production example.
