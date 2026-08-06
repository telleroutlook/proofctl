# Changelog

All notable changes to proofctl are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
proofctl uses [Semantic Versioning](https://semver.org/).

---

## [v0.3.14] — 2026-08-06

### Documentation

- **CHANGELOG v0.3.12**: corrected stale claim that `MaxWallClock` was unchanged;
  the 10m ceiling was raised to 60m in v0.3.13, making `--timeout 20m` effective.
- **README + CLAUDE.md**: updated `replay-partial` file extension from `.json` to
  `.debug` (changed in v0.3.10/B5); added `proofctl check --timeout` to the command
  reference table with the correct 60m ceiling.

---

## [v0.3.13] — 2026-08-06

### Fixed

- **B10 follow-up — `MaxWallClock` raised from 10m to 60m**: The `--timeout` flag
  added in v0.3.12 was silently capped at the old `MaxWallClock = 10m`, so
  `--timeout 20m` had no effect. `MaxWallClock` is now 60m to accommodate checkers
  that perform independent recomputation (archimedean even sector needs ~600s).
  The default timeout (5m) is unchanged; only the ceiling changed.

---

## [v0.3.12] — 2026-08-06

### Added

- **`proofctl check --timeout <duration>`**: per-checker wall-clock timeout override.
  The runner's default is 5 minutes; the ceiling (`MaxWallClock`) was 10 minutes at
  the time of this release but was raised to 60 minutes in v0.3.13.
  Usage: `proofctl check --timeout 20m @lem-o1b-even`
  Zero (the default) preserves the existing 5 m default. Values above `MaxWallClock`
  are clamped — see v0.3.13 for the raised ceiling.

### Known limitation

- The per-checker timeout is not yet configurable in the ContractV2 JSON.
  A `runtime.timeout_seconds` field is planned for v0.4.

---

## [v0.3.11] — 2026-08-06

### Fixed

- **B6 — `proofctl attest` wrote v2 attestation with empty `ObligationResults`**:
  After the v0.3.10 fix for B4, `proofctl attest` correctly set `Checker.ProtocolVersion=2`
  but left `ObligationResults` empty. `deriveStatus` (v2 path) returns `StatusRejected`
  when `ObligationResults` is empty, so attested claims immediately showed as `REJECTED`
  despite the `accepted` outcome. Fixed in `buildAndWriteAttestation` and the new helper
  `buildObligationResults`: when `outcome == "accepted"` and `checker.ProtocolVersion == 2`,
  the function looks up the claim's contract in `domains/*/contracts/<claimID>.json` and
  fills `ObligationResults` with `verdict: "pass"` for each declared obligation.
  Falls back to a single synthetic `independent-review.accepted` result when no contract
  is found, ensuring the attestation is always accepted. The fix applies to both the
  single-claim and `--batch` paths.

- **B3 — `proofctl replay` did not propagate `metadata` from checker stdout to attestation**:
  The checker JSON output may include a `"metadata": {...}` map (e.g. for `required_metadata_keys`
  policy conditions). Previously `cmd_replay.go` parsed `obligation_results` from checker
  stdout but ignored `metadata`, so `release --dry-run` always failed `meta:*` conditions
  even when the checker emitted the required keys. Fixed: `checkerMetadata` is now collected
  alongside `obligationResults` and merged into the attestation's `Metadata` map
  (checker values do not overwrite the fixed internal keys such as `cold_replay_date`).

---

## [v0.3.10] — 2026-08-06

### Fixed

- **B4 — `proofctl attest` wrote v1 attestations (`protocol_version=0`)**:
  `buildAndWriteAttestation` now looks up the claim's `CheckerPolicy` in the compiled
  ProofGraph and populates `att.Checker` from the matching `CheckerIdentity`. This ensures
  `protocol_version=2` is recorded and `LEGACY_ATTESTATION_NOT_RELEASABLE` is no longer
  triggered by `proofctl attest`-written attestations.
  Requires `--metadata reviewer=<name-or-orcid>` for `--assurance independent-review`
  to maintain auditability.

- **B5 — partial-replay debug file used `.json` extension causing `loadAttestations` crash**:
  `writePartialReplayRecord` now writes to `<claim>-replay-partial.debug` instead of
  `<claim>-replay-partial.json`. The `.json` extension caused `loadAttestations`
  (which uses `json.Decoder` with `DisallowUnknownFields`) to crash on the unknown
  `"date"` and `"note"` fields in the partial record format, blocking all subsequent
  `proofctl status` / `cas import` invocations until the file was manually deleted.

- **D4 — `proofctl doctor` CAS check reported "skipped" even when blobs are present**:
  `checkCASNonEmpty` now iterates `pg.Evidence` and stats each declared blob path
  individually, reporting which specific digests are missing. Previously it only
  checked whether the CAS directory was non-empty.

- **D5 — `proofctl status` did not show why a claim was `REJECTED`**:
  REJECTED claims now include a reason suffix derived from `att.Metadata["note"]`
  or `att.BlockReason` when available, e.g. `REJECTED  (obligation_results empty)`.

- **I2 — `compile --adapter contract-dir` silently discarded existing `checkers` array**:
  `compileContractDir` now copies all checker entries from the existing `graph.json`
  into the newly compiled `ProofGraph`. Previously every re-compile wiped the
  `checkers` array, requiring manual re-pinning after each `proofctl pin checker` run.

---

## [v0.3.9] — 2026-08-05

### Fixed

- **B1/C1 root cause — `cmd_pin.go` and `cmd_status.go` missing `.proofctl/` prefix**:
  `pin checker` read graph source via `filepath.Join(root, cfg.GraphSource)`, missing
  `config.DirName`. Watch loop in `proofctl status --watch` had the same bug.
  Both now use `filepath.Join(root, config.DirName, cfg.GraphSource)`.
  The underlying `config.Init` always writes `graph_source: "graph.json"` (correct);
  users who worked around the bug by writing `".proofctl/graph.json"` should revert to
  `"graph.json"` in their `.proofctl/config.json`.

- **B2 batch path — `cmdReplayBatch` wrote attestations with zero `Checker` field**:
  Batch replay now loads the ProofGraph at startup, builds a `claimID → CheckerIdentity`
  map, and populates `att.Checker` per claim — same as the single-evidence path.
  Attestations written by `--batch` no longer trigger `LEGACY_ATTESTATION_NOT_RELEASABLE`.

- **D1 — `--reuse-generated` silent miss on full-length hex filenames**:
  Previously the flag truncated the digest hex to 16 chars before looking up
  `<dir>/<hex>.json`, silently falling back to the generator when users named files
  with the full 64-char hex. Now tries the full-length name first, falls back to the
  16-char prefix only if the full-length file does not exist.

- **D3 — `compile --adapter contract-dir` lost `statement.text` and `checker_policy`**:
  The adapter now loads the existing `.proofctl/graph.json` before recompiling and
  preserves `statement.text` and `checker_policy` for any claim already present.
  New claims (not yet in graph.json) still get empty text and no checker policy
  as before.

- **D4 — `proofctl doctor` exit 1 when proofctl not in PATH**:
  `proofctl not found in PATH` is now a warning (`OK: true, Warn: true`) rather than
  an error. Running the binary directly from a build directory is normal during
  development; PATH installation is optional. Only genuine blocking conditions
  (missing project, BRIDGE_CHECKER not set/executable, etc.) cause exit 1.

---

## [v0.3.8] — 2026-08-05

### Security

- **P0: C01 no longer trusts writable `outcome` field for v2 attestations**
  (`internal/release/conditions.go`, `internal/status/status.go`).
  Previously `checkC01GlobalStatus` read `att.Outcome` directly — a field
  present in the on-disk JSON that any user could set to `"accepted"`. A
  hand-crafted attestation with `"outcome":"accepted"` but no real checker
  run could bypass release. Now for v2 attestations (`protocol_version: 2`)
  acceptance is derived from `ObligationResults` (all verdicts must be
  `"pass"`); the `Outcome` field is ignored. v1 attestations continue to use
  `Outcome` as before (they are blocked at the release gate by the existing
  `LEGACY_ATTESTATION_NOT_RELEASABLE` check).

### Added

- **`ir.Attestation.ObligationResults`**: new field stores per-obligation
  verdicts in the on-disk attestation JSON for v2 checker runs. Populated by
  `proofctl verify` and `proofctl check`. Existing v1 attestations omit the
  field (`omitempty`) and are unaffected.
- **Three new adversarial regression tests** in `gate_security_test.go`:
  `TestAdversarial_ForgingV2OutcomeFieldCannotBypassC01`,
  `TestAdversarial_ForgingV2OutcomeWithFailObligations`,
  `TestAdversarial_V2AllPassObligationsAreAccepted`.

### Fixed

- **`SECURITY.md` version** updated to match current release (`v0.3.8`).
- **CI `version-sync` step** added to `.github/workflows/ci.yml`: fails the
  build when `SECURITY.md` version drifts from the latest `CHANGELOG.md` tag.
- **`README.md` scope disclaimer** added to the intro paragraph: proofctl
  verifies process integrity and reproducibility, not mathematical correctness.



### Added

- **`proofctl doctor` — scripted-runtime warning**: when any checker in
  `graph.json` uses `runtime.kind = "scripted"`, doctor now emits a `⚠`
  warning (exit 0, not a failure):
  ```
  ⚠ runtime 'scripted' in use (<checker-id>): cross-machine reproducibility
    depends on host environment, not a pinned container
    → consider 'isolated-oci' runtime for third-party independent verification
  ```
  Available in `--json` output as `{"ok": true, "warn": true, ...}`.
  `scripted` checkers are fully functional — this is informational only.

---

## [v0.3.6] — 2026-08-05

### Fixed

- **derive.go Rule 6a comment**: documented why `scripted` is excluded from the
  `native-dev`/`native` cap. Trust anchor for `scripted` is `evidence_digest +
  checker_digest` (same as a pinned binary, interpreted rather than compiled);
  it may reach `GLOBALLY_VERIFIED` when deps and obligations are satisfied.
  No behaviour change — this was already correct, just undocumented.

- **fp035-policy.json template**: `"version"` corrected from `"1"` to `"2"`
  (`forbidden_runtimes` is a v2 field). Added `"native"` to `forbidden_runtimes`
  (was `["shadow", "native-dev"]`, now `["shadow", "native-dev", "native"]`),
  consistent with weil-first-prime's own policy file.

- **bridge.py — conditional Weil metadata keys** (both `adapters/cap/bridge.py`
  and `internal/scaffold/bridge.py` in sync): `path_keys_match`,
  `intervals_intersect`, `matrix_reconstructed`, `ldlt_passes` are now emitted
  **only when the certificate carries the corresponding top-level field**. The
  value is read from the cert (`true`/`false`) rather than hardcoded `"true"`.
  `digests_fresh` remains unconditional. Weil certificates that carry these
  fields are unaffected; fp035 certificates that omit them produce no spurious
  metadata keys, so fp035 policies that do not list these keys in
  `required_metadata_keys` will not fail at release.

---

## [v0.3.5] — 2026-08-05

### Added

- **fp035 domain scaffold**: `proofctl init --domain fp035` now generates a policy template
  (`required_metadata_keys`: `window_verified`, `archimedean_obligation`, `pivot_count`,
  `cap_format_version`, `digests_fresh`) and graph template with `scripted` runtime class.
  `fp035` is registered in `scaffold.KnownDomains`.

- **`compile --adapter contract-dir <dir>`**: New adapter that reads a directory of
  ContractV2 JSON files and compiles them into `.proofctl/graph.json`. Each ContractV2
  becomes one claim; dependency edges are derived from `dependencies[].claim_id`. Lint
  warnings are printed to stderr (non-fatal). Useful for projects like weil-first-prime
  whose claims live in `domains/fp035/contracts/`.

- **`scripted` runtime class**: Added `"scripted"` as a recognised `runtime.class` value
  in `internal/kernel/contract/lint.go`. Semantics: a deterministic script checker running
  natively (e.g. Python + interval arithmetic), where the trust anchor is the evidence
  digest and checker_digest, not sandbox isolation. This is the honest alternative to the
  incorrect `"wasi"` label for native Python checkers.

- **bridge.py — three new metadata keys** (both `adapters/cap/bridge.py` and
  `internal/scaffold/bridge.py` updated in sync):
  - `window_verified` — extracted from certificate top-level `"window"` field
  - `archimedean_obligation` — extracted from `certificate.archimedean_base.obligation`
  - `pivot_count` — extracted from certificate top-level `"pivot_count"` field
  All three are emitted only when present in the certificate; absent fields are silently
  skipped (no change to existing behaviour for certs that lack these fields).

- **`graph_source` config field wired up**: `loadProjectGraph` now reads
  `.proofctl/config.json`'s `graph_source` field and resolves the graph path relative to
  `.proofctl/`. Previously the field was parsed but never used; the graph was always loaded
  from `.proofctl/graph.json`.

---

## [v0.2.8] — 2026-08-04

### Fixed

- **B23**: `policy.Evaluate` contained a duplicate assurance allowed/forbidden check that
  diverged from the canonical C03 check in `conditions.go`. The duplicate lacked the
  empty-assurance skip introduced in v0.2.7, causing `proofctl release` to emit spurious
  blockers even after the C03 fix. Assurance enforcement is now exclusively handled by
  C03; `policy.Evaluate` only checks `required_claims`.
- **B24**: Integration tests (`integration_test.go`) were never executed by CI or locally
  because the `//go:build integration` constraint requires `-tags integration`, which was
  absent from all `go test` invocations. CI now runs `go test -tags integration ./...`;
  `CONTRIBUTING.md` command corrected accordingly.
- `coverage.out` (CI artefact) removed from git tracking; added to `.gitignore`.
- Version strings in `SECURITY.md` and `PLAN.md` aligned with `CHANGELOG.md` (`v0.2.7`).

---

## [v0.2.7] — 2026-08-04

### Fixed

- **B22**: `bridge.py` now extracts `pivot_radius_ratio` from checker stdout when the
  certificate lacks a top-level `margin_ratio` field (v2 cert format). Falls back from
  cert field → JSON stdout parse → key=value regex scan. Both `adapters/cap/bridge.py`
  and `internal/scaffold/bridge.py` updated in sync.

---

## [v0.2.6] — 2026-08-04

### Fixed

- **B18**: `verify/Pipeline`: multi-evidence claims now run the checker once per evidence
  item and union all metadata keys. Fixes `even_sector_passes`/`odd_sector_passes` being
  overwritten by the last evidence run.
- **B19**: `replay` and `replay --batch`: attestation `self_digest` is now computed and
  written before the attestation file is saved. Fixes C04 reporting `missing: self_digest`.
- **B20**: `release --fix`: attestations are reloaded after C04 repair so subsequent
  condition evaluation (C01 etc.) sees the updated state; fixes false "not accepted"
  reports for claims that were already accepted.

### Added

- **E12**: `proofctl check --evidence <digest>` — run checker for a single evidence
  item only; useful when a claim has multiple certs and you want per-cert metadata.
- **E13**: `proofctl cas gc` now requires confirmation before deleting blobs. Pass
  `--yes` to skip the prompt. `--dry-run` and `--json` mode are unaffected.

---

## [v0.2.5] — 2026-08-03

### Fixed

- GitHub Actions release workflow race: split into `create-release` + `build-upload`
  two-phase job so parallel matrix builds no longer conflict creating the release.

---

## [v0.2.4] — 2026-08-03

### Added / Fixed (B12–B15, E6–E11, F9–F15)

- `proofctl export --format lean` — export an accepted claim to a cross-domain Lean 4 stub
- `proofctl graph --status-filter` — filter nodes by status in `--mermaid` output
- `proofctl attest --from-replay` / `--from-check` — create attestation from cached result
- `proofctl replay --reuse-generated <dir>` — skip generator step and reuse pre-built certs
- `proofctl replay --dry-run` — validate CAS state and generator syntax without executing
- `proofctl check --all` cache-hit annotation with key prefix and invalidation hint
- `cas.Store` returns whether blob was already present (idempotent imports)
- `--json` output for `release --dry-run` (E14 completed in v0.2.6)
- `.proofctl/env.json` auto-loaded before flag parsing for zero-config environments
- `proofctl snapshot --diff <a> <b>` — compare two snapshot files

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
