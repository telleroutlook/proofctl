# Changelog

All notable changes to proofctl are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
proofctl uses [Semantic Versioning](https://semver.org/).

---

## [v0.1.0] — 2026-08-03

First tagged release. Covers Milestones 1–7 of the platform roadmap.

### Core platform (M1–M3)

- Release conditions C01–C04 are data-driven (no Go constants for domain specifics)
- `proofctl init` no longer hardcodes a default policy
- `ReleaseStatus` fields are domain-agnostic (`release_target` replaces `certified_radius`)

### CAP domain support (M4–M6)

- `adapters/cap/bridge.py` — protocol bridge for JSON-certificate checkers (stdlib only)
- `proofctl compile --fix-digests` — auto-fills zero statement digests from `sha256(statement.text)`
- `proofctl pin checker` — hashes checker script and writes `checker_digest` + `Runtime.Cmd`
- `proofctl cas import` — imports evidence files into the content-addressed store

### Platform scaffold (M3, M5)

- `proofctl init --domain <name>` — generates graph + policy + bridge for `cap`, `lrat`, `qmd`
- `proofctl domains list` — lists all known domains with POLICY/GRAPH/BRIDGE flags
- Domain templates: `cap`, `lrat`, `qmd`; negative test scaffold for CAP

### Operational commands (M4–M5)

- `proofctl replay` — cold-start generator+checker pipeline, single or multi-evidence
- `proofctl env verify|snapshot` — environment check and snapshot
- `proofctl verify --project` — parallel topological verification (T14)
- `proofctl status`, `proofctl snapshot`, `proofctl release`

### Release outputs (M4, M7)

- `.proofctl/STATUS.json` — written on every `proofctl release` (pass or fail)
- `.proofctl/release-snapshot.json` — written on pass; includes per-evidence metadata
- `release-manifest.json` — written to `ProjectRoot` on pass

### Path portability (M7)

- `graph.json` checker `cmd` supports `${VAR}` expansion and relative paths
- Multi-evidence replay: `--evidence`/`--generator` pairs, single attestation per claim

### Engineering health (M8)

- `gofmt` compliance enforced in CI
- All 17 subcommands visible in `proofctl --help`
- `internal/release` and all core packages ≥80% test coverage
- CLI integration tests (`cmd/proofctl/main_test.go`)
- Fuzz corpus for `FuzzDecodeStrict_Claim` and `FuzzCanonicalJSON` committed
- CI: bridge.py sync check, daily fuzz job, race detector

[v0.1.0]: https://github.com/telleroutlook/proofctl/releases/tag/v0.1.0

---

## [v0.2.3] — 2026-08-03

### Added

- `proofctl env snapshot --force` — prevents silently overwriting an existing lock file (B4)
- `proofctl attest --assurance independent-review` now requires `--key <keyfile>` or `PROOFCTL_SIGNING_KEY`; self-declaration without a verifiable identity is rejected (B5/F6)
- `proofctl cache invalidate <claim>` — removes cached attestation to force re-run on next check (B6)
- `proofctl cache show-key <claim>` — prints the cache key and explains what inputs compose it (B6)
- `proofctl check --no-cache` — skips cache lookup and re-runs checker unconditionally (B6)
- `proofctl check --all` — runs checkers for all claims with a `checker_policy`, outputs pytest-style summary (E4)
- `proofctl attest --batch <manifest.json>` — attests multiple claims from a JSON array in one invocation (E3)
- `proofctl attest diff <claim>` — shows field-level diff between current and previous attestation (git-backed) (F7)
- `proofctl cas import-dir <dir> [--pattern <glob>]` — bulk-imports files matching a glob pattern (F5)
- `proofctl status --watch` — polls `.proofctl/` every 2 s and re-prints status on any change (E7)
- `ir.AssuranceLevel()` — exported assurance rank function; replaces the ad-hoc `isHigherAssurance` boolean in compile (E5)
- `proofctl attest` now blocks assurance downgrades (`deterministic-cap` → `shadow-review`) unless `--force` is given (E5)
- `proofctl pin checker` warning now lists accepted lockfile formats with examples (B7)

### Changed

- `proofctl check` cache-hit annotation now shows the key prefix and how to invalidate it

### Fixed

- `isHigherAssurance` in `cmd_compile.go` delegated to `ir.AssuranceLevel` — single source of truth for assurance ordering

[v0.2.3]: https://github.com/telleroutlook/proofctl/releases/tag/v0.2.3
[v0.2.2]: https://github.com/telleroutlook/proofctl/releases/tag/v0.2.2
[v0.2.1]: https://github.com/telleroutlook/proofctl/releases/tag/v0.2.1
[v0.2.0]: https://github.com/telleroutlook/proofctl/releases/tag/v0.2.0
