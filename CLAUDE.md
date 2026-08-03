# CLAUDE.md — proofctl development rules

## Project identity

proofctl is a **mathematical proof certification platform** (not a Weil-specific tool).
The core engine (`internal/`) has zero domain knowledge. Domain specifics live in
`adapters/`, `internal/weil/`, `internal/lrat/`, and policy JSON files.

## Architecture invariants

- `internal/` packages must import zero domain-specific packages outside `internal/weil`
  and `internal/lrat`. Adding Weil/LRAT logic to `internal/dag`, `internal/release`,
  `internal/policy`, etc. is forbidden.
- Release conditions C01–C04 are universal and fixed. Domain-specific conditions come
  exclusively from `policy.RequiredMetadataKeys` in the policy JSON — never from Go constants.
- `adapters/cap/bridge.py` and `internal/scaffold/bridge.py` must stay in sync (bridge.py
  is the canonical source; scaffold embeds it for `proofctl init --domain cap`).
- `internal/scaffold/bridge.py` is embedded via `//go:embed`. Any change to bridge.py
  requires rebuilding the binary.

## Go conventions

- After any Go change: `go build ./...` then `~/go/bin/staticcheck ./...`
- After any test change: `go test ./...` — zero failures is the bar
- No `// nolint` comments without a justification comment on the same line
- Error strings: lowercase, no trailing period, wrap with `%w` for sentinel matching

## Python conventions (bridge.py, adapters/cap/)

- `bridge.py` is stdlib only — no imports outside the standard library
- Never add `float()` calls; all numeric values stay as strings passed through from certificates
- `BRIDGE_CHECKER` env var is the only configuration surface; no config files

## Policy JSON conventions

- Every new domain gets its own policy file in `policies/<domain>-v1.json`
- `required_metadata_keys` lists the keys that `adapters/cap/bridge.py` (or equivalent)
  populates on checker exit 0; keep them in sync with the bridge
- `target` must be the root theorem claim ID (the single claim that represents "proof complete")

## Scaffold conventions

- Templates live in `internal/scaffold/templates/`; bridge lives at `internal/scaffold/bridge.py`
- `scaffold.KnownDomains` is the single registry — add new domains here, not in cmd files
- `proofctl init --domain <name>` must be idempotent (no-op if files already exist)

## weil-lower-bound integration

- `graph.json`, `policies/weil-cap-v1.json`, `.proofctl/config.json` are in the
  weil-lower-bound repo (not here)
- The 12-claim DAG mirrors `internal/weil/defects.go` — if defects.go changes,
  update weil-lower-bound/graph.json accordingly
- `BRIDGE_CHECKER` for weil: `python3 checker/check_certificate.py`

## What NOT to do

- Do not hardcode Weil claim IDs, metadata keys, or D-numbers in `internal/release/`
- Do not add domain-specific `if domain == "weil"` branches anywhere in `internal/`
- Do not change `bridge.py` to import non-stdlib modules
- Do not write `certified_radius` anywhere — the field is `release_target`
