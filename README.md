# proofctl — Proof Graph Engine

`proofctl` is a content-addressed, evidence-aware, multi-backend, fail-closed mathematical
Proof Graph Engine. It manages claims, dependencies, evidence, checkers, trust types, cache,
and release status for formally verified mathematical software.

Claims are nodes in a directed acyclic graph. Each claim carries a content-addressed statement
digest, a list of dependencies, required assurance levels, evidence references, and a checker
policy. The engine verifies claims by invoking pinned checkers against pinned evidence, records
attestations with full provenance, and enforces a release gate that is fail-closed by default.
The current certified radius is `null` until the release gate passes.

## Project Status

**Phase**: 4 complete, Phase 5 in progress  
**certified_radius**: `null` — release gate has not passed  
**Shadow integration**: Weil claim graph compiled in shadow mode; D4, D8, D18 blockers reproduced

### Phase completion

| Phase | Title | Status |
|---|---|---|
| 0 | Dual-track freeze | complete |
| 1 | Spec-first | complete |
| 2 | Go Core MVP | complete |
| 3 | Checker runner + evidence identity | complete |
| 4 | Weil shadow integration | complete |
| 5 | Weil cutover + formal release gate | in progress |
| 6 | QMD/Markdown frontend | — |
| 7 | Second-domain generality | — |

### Running the Weil shadow integration

```bash
mkdir myproject && cd myproject
proofctl init
cp /path/to/proofctl/examples/weil/graph.json .
proofctl compile --adapter weil graph.json
proofctl status
proofctl release --dry-run --target @thm-main-radius-030
```

## Build

```
go build ./...
go vet ./...
go test ./...
```

Requires Go 1.22 or later.

## Project Layout

```
cmd/proofctl/      CLI entry point
internal/          Core engine packages (not for external import)
  ir/              Intermediate representation: types and strict decoder
  dag/             Claim dependency graph (DAG validation, closure, impact)
  cas/             Content-addressed storage (sha256, atomic writes)
  checker/         Checker identity and cache-key derivation
  runner/          Checker runner interface and native subprocess runner
  freshness/       File-level freshness snapshots and drift detection
  policy/          Release policy evaluation
  attestation/     Attestation combination and self-digest
  status/          Global status projection over the claim graph
  release/         Release gate (dry-run + atomic STATUS.json write)
  snapshot/        Point-in-time immutable graph snapshots
  compile/         Source compiler (text -> ProofGraph IR)
pkg/protocol/      Public types for external checker use
adapters/          Backend adapters (Weil, QMD, Lean)
schemas/           JSON Schema draft-07 for all wire types
policies/          Release policy files
docs/              Design and protocol documentation
  ADR/             Architecture Decision Records
examples/          Integration examples
testdata/          Golden outputs, adversarial inputs, fuzz corpora
```

## Documentation

- [Threat Model](docs/THREAT_MODEL.md)
- [ProofGraph IR](docs/PROOFGRAPH_IR.md)
- [Checker Protocol](docs/CHECKER_PROTOCOL.md)
- [Assurance Model](docs/ASSURANCE_MODEL.md)
- [Weil Acceptance Criteria](docs/WEIL_ACCEPTANCE.md)
- [ADR-001: Trust Boundaries](docs/ADR/ADR-001-trust-boundaries.md)
- [ADR-002: Content-Addressed Identity](docs/ADR/ADR-002-content-addressed-identity.md)
- [ADR-003: Assurance Model](docs/ADR/ADR-003-assurance-model.md)
- [ADR-004: Release Gate](docs/ADR/ADR-004-release-gate.md)

## Status

`certified_radius=null` — the release gate has not yet passed.
