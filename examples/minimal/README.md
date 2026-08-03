# Minimal Demo — Parity Arithmetic

This self-contained example walks through the full proofctl workflow:
**init → compile → replay → release** using a toy proof about parity arithmetic.

No external checker is needed. `checker/check.sh` is a shell script that always
returns `accepted` — it plays the role a real SAT solver or interval-arithmetic
checker would fill in a production proof.

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

### 4. Replay each claim

`proofctl replay` runs the generator (here a trivial `echo`), passes the output
to the checker, and records the attestation.

```sh
# Create a dummy certificate file for each claim.
echo '{"result":"even+even=even"}' > /tmp/cert-even-sum.json
echo '{"result":"odd+even=odd"}'  > /tmp/cert-odd-plus-even.json
echo '{"result":"parity ok"}'     > /tmp/cert-parity-main.json

proofctl replay \
  --claim lem-even-sum \
  --evidence sha256:$(sha256sum /tmp/cert-even-sum.json | awk '{print $1}') \
  --generator "cp /tmp/cert-even-sum.json {cert}"

proofctl replay \
  --claim lem-odd-plus-even \
  --evidence sha256:$(sha256sum /tmp/cert-odd-plus-even.json | awk '{print $1}') \
  --generator "cp /tmp/cert-odd-plus-even.json {cert}"

proofctl replay \
  --claim thm-parity-main \
  --evidence sha256:$(sha256sum /tmp/cert-parity-main.json | awk '{print $1}') \
  --generator "cp /tmp/cert-parity-main.json {cert}"
```

### 5. Check status (all accepted)

```sh
proofctl status
```

All three claims should now be `accepted`.

### 6. Release

```sh
proofctl release --policy policies/minimal-v1.json
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
| `replay` | Generator → checker pipeline; attestation write |
| `status` | DAG-aware status propagation |
| `release` | Fail-closed gate; C01–C04 universal conditions |

## Adapting for a real proof

Replace `checker/check.sh` with your domain checker (SAT solver, interval
arithmetic library, formal-kernel verifier, etc.). The checker must:

1. Accept a certificate file path as `$1`
2. Print a JSON object to stdout matching the [checker protocol](../../pkg/protocol/)
3. Exit `0` on success, non-zero on failure

See `adapters/cap/bridge.py` for a production example.
