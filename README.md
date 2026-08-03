# proofctl — Mathematical Proof Platform

`proofctl` is a content-addressed, evidence-aware, fail-closed **mathematical proof certification platform**. It provides the infrastructure layer for computer-assisted proof (CAP) projects: DAG management, content-addressed storage, attestation chains, freshness tracking, and a release gate.

Mathematical projects provide:
1. A **claim graph** (`graph.json`) — a DAG of lemmas and theorems
2. A **domain checker** — any executable that verifies a certificate file
3. A **release policy** (`policies/*.json`) — declares which claims and metadata keys must be satisfied

proofctl provides everything else.

## Try it now — self-contained demo

No external checker or separate repository needed:

```sh
cd examples/minimal
proofctl init --policy policies/minimal-v1.json
proofctl compile --fix-digests graph.json
proofctl status          # all open
# ... replay each claim (see examples/minimal/README.md for full commands)
proofctl release --policy policies/minimal-v1.json
cat .proofctl/STATUS.json  # "released": true
```

See [`examples/minimal/README.md`](examples/minimal/README.md) for the complete step-by-step walkthrough.

## Quick Start — New CAP Project

```bash
mkdir my-proof && cd my-proof
proofctl init --domain cap
# Edit graph.json: replace placeholder claims with your theorem structure
# Edit policies/cap-v1.json: set target to your main theorem ID
# Set BRIDGE_CHECKER to your checker, e.g.:
#   export BRIDGE_CHECKER="python checker/check_certificate.py"
proofctl compile --adapter json graph.json
proofctl status
proofctl release --dry-run
```

## Quick Start — weil-lower-bound (reference domain)

The `weil-lower-bound` repository is the first reference implementation. Its
`.proofctl/` directory, `graph.json`, and `policies/weil-cap-v1.json` are already
in place. From the `weil-lower-bound` directory:

```bash
# PROOFCTL_ADAPTERS must point to the adapters/ directory of a proofctl checkout.
# The env var is expanded in graph.json checker cmd entries at runtime.
export PROOFCTL_ADAPTERS=/path/to/proofctl/adapters

proofctl status          # shows 12 claims, 7 accepted
proofctl graph           # shows full DAG
proofctl release --dry-run   # lists all unmet conditions
```

## Known Domains

```
proofctl domains list
```

| Domain | Bridge | Description |
|--------|--------|-------------|
| `cap`  | yes    | Computer-Assisted Proof via JSON certificate + standalone checker |
| `lrat` | —      | LRAT SAT solver: formula → unsat → verified 3-claim graph |
| `qmd`  | —      | Quarto/Pandoc: extract claims from `<div class="claim">` blocks |

## Build

```bash
go build ./...
go test ./...
~/go/bin/staticcheck ./...
~/go/bin/golangci-lint run ./...
```

Requires Go 1.22 or later. A pre-commit hook that runs all checks is installed automatically by cloning — see `.git/hooks/pre-commit`.

## Project Layout

```
cmd/proofctl/          CLI entry point (17 subcommands)
internal/
  ir/                  Intermediate representation types and strict decoder
  dag/                 Claim DAG (validation, closure, impact, frontier)
  cas/                 Content-addressed blob store (sha256, atomic writes)
  checker/             Checker identity pinning and cache-key derivation
  runner/              Checker runner interface and native subprocess runner
  freshness/           File-level freshness snapshots and drift detection
  policy/              Release policy evaluation (required_claims, assurances, metadata keys)
  attestation/         Attestation combination and self-digest
  status/              Global status projection over the claim graph
  release/             Release gate (dry-run + atomic STATUS.json write + release-snapshot.json, 4 universal conditions)
  snapshot/            Point-in-time immutable graph snapshots
  compile/             Source compiler (JSON → ProofGraph IR)
  config/              .proofctl project directory management
  scaffold/            Domain scaffolding (Go embed: templates + bridge.py)
  weil/                Weil-domain defect table and shadow attestations
  lrat/                LRAT SAT domain types
pkg/protocol/          Public wire types for external checker processes (stable API)
adapters/
  cap/                 CAP bridge: proofctl wire protocol ↔ python checker (bridge.py)
  weil/                Weil claim graph adapter (shadow mode)
  qmd/                 Quarto/Pandoc QMD adapter
  lrat/                LRAT problem spec adapter
  lean/                Lean 4 adapter (stub)
policies/
  weil-release-v1.json Weil domain release policy (12 claims + 9 metadata keys)
  lrat-release-v1.json LRAT domain release policy (placeholder)
schemas/               JSON Schema draft-07 for all wire types
docs/                  Design docs, ADRs, protocol specification
examples/              Integration examples
testdata/              Golden outputs, adversarial inputs, fuzz corpora
```

## Release Policy Format

A policy file controls what `proofctl release` requires:

```json
{
  "version": "1",
  "target": "thm-my-main-theorem",
  "allowed_assurances": ["deterministic-cap", "formal-kernel", ...],
  "forbidden_assurances": ["ai-review", "assumption", "shadow-review"],
  "required_claims": ["lemma-a", "lemma-b", "thm-my-main-theorem"],
  "required_metadata_keys": ["cap_format_version", "ldlt_passes", ...]
}
```

`required_metadata_keys` are domain-specific keys that at least one checker attestation
must provide. The `cap` domain uses 9 keys populated by `adapters/cap/bridge.py`.

## Release Gate Conditions

Every `proofctl release` evaluates:

| ID | Condition | Type |
|----|-----------|------|
| `C01-global-status-accepted` | All claims accepted | Universal |
| `C02-assumption-footprint-empty` | No `assumption` assurance | Universal |
| `C03-assurances-allowed` | All assurances pass policy | Universal |
| `C04-replay-consistency` | All attestations have freshness/digest | Universal |
| `meta:<key>` × N | Each `required_metadata_keys` entry present | Domain-specific |

## Cold-Start Replay

`proofctl replay` re-runs the certificate generator from scratch, hashes the output,
compares it against the pinned evidence digest, and runs the checker — writing an
`exact-replay` attestation only when all checks pass.

**Flags:**
- `--semantic` — skip exact digest comparison; accept checker-pass only (useful when source files changed but math is correct)
- `--dry-run` — validate CAS state and generator syntax without running the generator
- `--evidence` / `--generator` — repeatable pairs for multi-evidence claims

Single evidence (backward compatible):
```bash
proofctl replay \
  --claim thm-my-theorem \
  --generator "python -m src.generate --out {cert}" \
  sha256:<expected-digest>
```

Multi-evidence (one `--evidence`/`--generator` pair per certificate — for proofs
with multiple independent sectors or parameter values):
```bash
BRIDGE_CHECKER="python3 checker/check_certificate.py" \
proofctl replay \
  --claim thm-main-radius-030 \
  --evidence sha256:<odd-digest>  --generator "python -m src.gen --sector odd  --out {cert}" \
  --evidence sha256:<even-digest> --generator "python -m src.gen --sector even --out {cert}"
```

Semantic replay (source changed, math correct):
```bash
proofctl replay --semantic \
  --claim thm-main-radius-030 \
  --evidence sha256:<digest> --generator "python -m src.gen --out {cert}"
```

Dry-run (check CAS state without running generator):
```bash
proofctl replay --dry-run \
  --claim thm-main-radius-030 \
  --evidence sha256:<digest> --generator "python -m src.gen --out {cert}"
```

All evidence items must pass (digest match + checker exit 0) before a single
`exact-replay` attestation is written to `.proofctl/attestations/<claim-id>-replay.json`.
On partial failure, a debug record `<claim-id>-replay-partial.json` is written showing
which items passed.

## Status Display

`proofctl status` shows claim status with enhanced diagnostics:

- `[UNVERIFIED_DIGEST]` — claim has a zero/placeholder `statement.digest`; run `proofctl compile --fix-digests`
- `OPEN (no attestation)` — evidence registered but not yet verified
- `OPEN (no evidence registered)` — claim has no evidence declared in graph.json
- `release_target` — read automatically from the policy file; shows which claim must be accepted for release

```bash
proofctl status             # human-readable
proofctl status --verbose   # includes toolchain versions for accepted claims
proofctl --json status      # machine-readable JSON: status, assurance, start_freshness,
                            # end_freshness, evidence_count per claim + open_reason/block_reason
```

## Checker Commands

```bash
proofctl check @<claim-id>                          # run checker against CAS evidence
proofctl check --all                                # run all claims with a checker_policy
proofctl check --no-cache @<claim>                  # force re-run, skip cache
proofctl check --evidence sha256:<d> @<claim>       # run checker for one evidence item only
```

The `--evidence` flag is useful when a claim has multiple certs (e.g. odd + even sectors)
and you want per-cert metadata independently before merging.

## CAS Management

```bash
proofctl cas import <file> [file ...]               # import evidence (shows EXISTS if already present)
proofctl cas import-dir <dir> --pattern "*.json"    # bulk import matching files
proofctl cas list                                   # list all stored blobs
proofctl cas gc --dry-run                           # preview unreferenced blobs
proofctl cas gc --yes                               # delete unreferenced blobs (skips confirmation prompt)
```

## Environment Checks

`proofctl doctor` actively checks that the environment is ready to run:

```
✓ proofctl in PATH
✓ .proofctl/ project found
✗ BRIDGE_CHECKER not set
  → export BRIDGE_CHECKER="python3 checker/check_certificate.py"
✓ PROOFCTL_ADAPTERS set
✓ checker pinned
✗ CAS is empty — no evidence imported yet
  → run 'proofctl cas import <cert-file>'
```

Exit 0 if all checks pass, exit 1 otherwise — safe to use in CI as `proofctl doctor || exit 1`.



On a successful `proofctl release`, in addition to `.proofctl/STATUS.json`,
proofctl writes `.proofctl/release-snapshot.json` with richer per-evidence metadata
aggregated from checker attestations:

```json
{
  "release_target": "thm-main-radius-030",
  "generated": "2026-08-03",
  "claim_summary": { "accepted": 12, "open": 0, ... },
  "evidence": [
    {
      "digest": "sha256:de3e...",
      "path_hint": "certificates/030/primary/odd.json",
      "metadata": { "ldlt_passes": "true", "pivot_radius_ratio": "3.3e8", ... }
    }
  ]
}
```

This file is machine-readable and can replace hand-maintained status files in
consumer repositories.

## License

Copyright 2026 telleroutlook. Licensed under the [Apache License, Version 2.0](LICENSE).

If you use proofctl in academic work, please cite:

```
proofctl: A mathematical proof certification platform.
https://github.com/telleroutlook/proofctl
```


- [Threat Model](docs/THREAT_MODEL.md)
- [ProofGraph IR](docs/PROOFGRAPH_IR.md)
- [Checker Protocol](docs/CHECKER_PROTOCOL.md)
- [Assurance Model](docs/ASSURANCE_MODEL.md)
- [Phase 7 Generality](docs/PHASE7_GENERALITY.md)
- [ADR-001: Trust Boundaries](docs/ADR/ADR-001-trust-boundaries.md)
- [ADR-002: Content-Addressed Identity](docs/ADR/ADR-002-content-addressed-identity.md)
- [ADR-003: Assurance Model](docs/ADR/ADR-003-assurance-model.md)
- [ADR-004: Release Gate](docs/ADR/ADR-004-release-gate.md)
