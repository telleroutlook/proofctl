# proofctl — Proof Graph Engine

`proofctl` is a content-addressed, evidence-aware, multi-backend, fail-closed mathematical
Proof Graph Engine. It manages claims, dependencies, evidence, checkers, trust types, cache,
and release status for formally verified mathematical software.

Claims are nodes in a directed acyclic graph. Each claim carries a content-addressed statement
digest, a list of dependencies, required assurance levels, evidence references, and a checker
policy. The engine verifies claims by invoking pinned checkers against pinned evidence, records
attestations with full provenance, and enforces a release gate that is fail-closed by default.
The current certified radius is `null` until the release gate passes.

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
  compile/         Source compiler (text -> ProofGraph IR)
pkg/protocol/      Public types for external checker use
adapters/          Backend adapters (Weil, QMD, Lean)
schemas/           JSON Schema draft-07 for all wire types
policies/          Release policy files
docs/              Design and protocol documentation
examples/          Integration examples
testdata/          Golden outputs, adversarial inputs, fuzz corpora
```

## Documentation

- [Threat Model](docs/THREAT_MODEL.md)
- [ProofGraph IR](docs/PROOFGRAPH_IR.md)
- [Checker Protocol](docs/CHECKER_PROTOCOL.md)
- [Assurance Model](docs/ASSURANCE_MODEL.md)
- [Weil Acceptance Criteria](docs/WEIL_ACCEPTANCE.md)

## Status

`certified_radius=null` — the release gate has not yet passed.
