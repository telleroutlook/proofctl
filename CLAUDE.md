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

- After any Go change: `go build ./...` then `~/go/bin/staticcheck ./...` then `~/go/bin/golangci-lint run ./...`
- After any test change: `go test ./...` — zero failures is the bar; all packages ≥80% coverage
- No `// nolint` comments without a justification comment on the same line
- Error strings: lowercase, no trailing period, wrap with `%w` for sentinel matching
- `defer f.Close()` must always be `defer func() { _ = f.Close() }()` — bare defer discards the error (errcheck)
- Non-deferred `f.Close()` results must be assigned: `_ = f.Close()` or checked

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
- checker `cmd` in graph.json uses `${PROOFCTL_ADAPTERS}/cap/bridge.py` — never
  absolute paths; `NativeRunner.resolveCmdPaths()` expands `${VAR}` at runtime

## replay conventions

- Single-evidence: `proofctl replay --claim <id> --generator "cmd {cert}" <digest>`
- Multi-evidence: `--evidence <digest> --generator <cmd>` repeated in pairs; all
  must pass before one attestation is written
- Never call `proofctl replay` twice for the same claim to work around the
  single-attestation-per-claim design — use multi-evidence pairs instead
- `--semantic` flag: skips exact digest comparison, accepts checker-pass only;
  writes `reproducible-computation` assurance instead of `exact-replay`
- `--dry-run` flag: validates CAS state and generator syntax without executing;
  reports which evidence is missing from CAS and whether path_hint can auto-import
- On partial failure, a debug record `<claim-id>-replay-partial.json` is written
  to `.proofctl/attestations/` showing per-evidence pass/fail with detailed reasons
- `bridge.py` exit codes: 0=certified, 1=uncertified, 2=malformed cert, 3=protocol error
  (missing BRIDGE_CHECKER env var → exit 3, not exit 2, to prevent useless backoff retries)

## status conventions

- `proofctl status` reads `release_target` from the policy file automatically
  (via `cfg.PolicyFile` in `.proofctl/config.json`) — no manual wiring needed
- OPEN claims show distinguishing reason: `(no attestation)` vs `(no evidence registered)`
- Zero/placeholder `statement.digest` (all-zeros sha256) is flagged `[UNVERIFIED_DIGEST]`;
  fix with `proofctl compile --fix-digests <source-file>`

## doctor conventions

- `proofctl doctor` checks: proofctl in PATH, project found, BRIDGE_CHECKER set,
  BRIDGE_CHECKER executable (uses exec.LookPath for bare names like `python3`),
  PROOFCTL_ADAPTERS set if needed by graph.json, checker pinned, CAS non-empty
- Exit 0 = all pass; exit 1 = any fail; safe to use as `proofctl doctor || exit 1` in CI

## error message conventions

- Every failure must include: what failed, which entity (claim ID / digest / file path),
  and why (the underlying OS or protocol error)
- Generator and checker failures in `replay` must include the full combined output
- Digest mismatches must diff `sha256_inputs` between old cert (from CAS) and new cert
- `cas list` walk errors are reported as warnings, not silently swallowed
- Policy file errors include the file path
- C04 release blockers name which specific fields are absent (self_digest, start_freshness, end_freshness)

## CI conventions

- CI runs: `go build`, `go vet`, `gofmt -l`, bridge.py sync check, `staticcheck`, 
  `golangci-lint`, `govulncheck`, `go test`, `go test -race`
- The pre-commit hook at `.git/hooks/pre-commit` runs the same checks locally
- The hook is not checked into git (it lives in `.git/hooks/`); new clones must
  copy it manually or run `cp .git/hooks/pre-commit.sample .git/hooks/pre-commit`
  (note: the hook is written fresh on each dev machine)



- `.proofctl/STATUS.json` — written by `proofctl release` (always, pass or fail)
- `.proofctl/release-snapshot.json` — written by `proofctl release` on pass only;
  contains per-evidence metadata; consumer repos should read this instead of
  maintaining their own STATUS.json
- Do not write `certified_radius` anywhere — the field is `release_target`
