# CLAUDE.md — proofctl development rules

## Project identity

proofctl is a **mathematical proof certification platform** (not a Weil-specific tool).
The core engine (`internal/`) has zero domain knowledge. Domain specifics live in
`adapters/`, `domains/`, `internal/weil/`, `internal/lrat/`, and policy JSON files.

## Architecture invariants

- `internal/kernel/` packages must import ONLY Go stdlib. No domain, orchestrator, or
  runner imports. Verified by `go list -deps ./internal/kernel/...` in CI.
- `internal/` packages (outside `internal/weil` and `internal/lrat`) must import zero
  domain-specific packages. Adding Weil/LRAT logic to `internal/dag`, `internal/release`,
  `internal/policy`, etc. is forbidden.
- Release conditions C01–C09 are universal or policy-driven. Domain-specific conditions
  come exclusively from `policy.RequiredMetadataKeys` in the policy JSON — never from
  Go constants. C09 (`ForbiddenRuntimes`) is activated via `policy.ForbiddenRuntimes`.
- `adapters/cap/bridge.py` and `internal/scaffold/bridge.py` must stay in sync (bridge.py
  is the canonical source; scaffold embeds it for `proofctl init --domain cap`).
- `internal/scaffold/bridge.py` is embedded via `//go:embed`. Any change to bridge.py
  requires rebuilding the binary.
- `testdata/adversarial/generality_test.go` scans `internal/kernel/`, `internal/release/`,
  and `pkg/protocol/v2/` for domain-specific identifiers — CI fails if any are found.

## v2 kernel architecture

The v2 trusted kernel lives in `internal/kernel/`:
- `identity/` — ClaimIdentity closure (sha256 of canonical inputs, INV-09)
- `attestation/` — AttestationV2 validation (self-digest, identity binding, signature, INV-02/03/04)
- `derive/` — State machine (OPEN→CANDIDATE→LOCALLY_VERIFIED→GLOBALLY_VERIFIED→REPRODUCIBLE→RELEASED→STALE→BLOCKED)
- `contract/` — ContractV2 lint (LintContract, INV-06 obligation exact-set)
- `policy/` — PolicyV2 (KeyAuth, role-assurance-runtime authorization, INV-04)
- `bundle/` — Release bundle types (Manifest, VerificationResult, INV-12)

`cmd/proofverify` is the offline verification binary — no network, no subprocess, no auto-repair.

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
- `BRIDGE_CHECKER` env var is the only configuration surface for CAP bridge; no config files
- bridge.py exit codes: 0=certified, 1=uncertified, 2=unavailable, 3=protocol error

## Domain conventions

- Every domain gets its own `domains/<name>/` directory with ContractV2 JSON + `policy-v2.json`
- Every ContractV2 must pass `proofctl contract lint` — CI enforces this via `domains-lint` job
- Known domains: cap, lrat, qmd, metamath, lean, coq, smt, isabelle, weil
- `scaffold.KnownDomains` is the single registry — add new domains here, not in cmd files
- `proofctl init --domain <name>` must be idempotent (no-op if files already exist)

## Policy JSON conventions

- v1 policy files: `policies/<domain>-v1.json` (legacy, backward compatible)
- v2 policy files: `domains/<domain>/policy-v2.json` (includes `forbidden_runtimes`, `forbidden_assurances`)
- `required_metadata_keys` lists the keys that the bridge populates on checker exit 0
- `target` must be the root theorem claim ID
- `forbidden_runtimes: ["shadow", "native-dev"]` prevents development results entering release (C09)

## weil-lower-bound integration

- `graph.json`, `policies/weil-cap-v1.json`, `.proofctl/config.json` are in the
  weil-lower-bound repo (not here)
- The claim DAG mirrors `internal/weil/defects.go` (D1–D18) — if defects.go changes,
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

## release conventions

- `proofctl release` evaluates C01–C09 conditions + domain metadata conditions
- `release --fix` was removed (Canvas §14: blockers must be fixed before release, not auto-repaired)
- `release --dry-run` is the safe path: evaluates conditions without writing STATUS.json
- C09 (`no-native-runtime`) is activated when `policy.ForbiddenRuntimes` is non-empty
- proofverify is the offline verifier: `proofverify bundle.verify <bundle-dir>`
- `proofctl release` 拒绝 v1 attestation（`LEGACY_ATTESTATION_NOT_RELEASABLE`）
- C05 现在调用真正的 Ed25519 验签（不只检查字段非空）

## status conventions

- `proofctl status` reads `release_target` from the policy file automatically
- OPEN claims show distinguishing reason: `(no attestation)` vs `(no evidence registered)`
- Zero/placeholder `statement.digest` (all-zeros sha256) is flagged `[UNVERIFIED_DIGEST]`;
  fix with `proofctl compile --fix-digests <source-file>`
- `proofctl status --verbose` shows toolchain versions for accepted claims

## doctor conventions

- `proofctl doctor` checks: proofctl in PATH, project found, BRIDGE_CHECKER set,
  BRIDGE_CHECKER executable (uses exec.LookPath for bare names like `python3`),
  PROOFCTL_ADAPTERS set if needed by graph.json, checker pinned, CAS non-empty
- Exit 0 = all pass; exit 1 = any fail; safe to use as `proofctl doctor || exit 1` in CI

## mutation testing conventions

- `proofctl mutate` runs the platform mutation catalog against current validators
- Kill rate must be 100%; exit 1 if any mutation survives
- Mutation fixtures live in `testdata/mutation/`; adversarial tests in `testdata/adversarial/`
- Canvas §13 mandatory mutations: all covered by `testdata/mutation/` + `testdata/adversarial/`

## bundle conventions

- `proofctl bundle create [--output <dir>]` — assembles release bundle (manifest + member digests)
- `proofctl bundle verify <bundle-dir>` — offline verification of all member digests (INV-12)
- `proofverify bundle.verify <bundle-dir>` — independent offline verifier (separate binary)
- Bundle format version must be "2"; format "1" is rejected

## verify conventions

- `proofctl verify @<claim-id>` — re-runs the checker and writes a new attestation
- `proofctl verify --project [--parallel N]` — verifies all open claims in dependency order
- `proofctl verify --signature-only @<claim-id>` — offline check without re-running the checker:
  verifies self_digest integrity, Ed25519 signature (against `.proofctl/keys/*.pub`), and
  presence of all evidence digests in CAS; exit 1 on any failure
- `proofctl verify --signature-only --project` — signature-only check over all claims
- Use `--signature-only` in CI session-start checks and downstream consumer repos to avoid
  checker binary digest mismatch while still enforcing cryptographic attestation integrity
- `proofctl verify` wires obligation IDs from ContractV2 JSON via `loadObligationIDs()`
- multi-evidence: any per-evidence failure blocks the whole claim (INV-07)

## security invariant conventions

- 12 个 Canvas 不变量（INV-01–INV-12）在 `SECURITY-INVARIANTS.md` 中有完整映射
- native-dev/native runtime 在 `internal/kernel/derive` Rule 6a 处被硬性上限到 LOCALLY_VERIFIED
- `pkg/protocol/v2/AllObligationsPass` 对空 ObligationResults 返回 false
- `internal/kernel/bundle/sign.go:CanonicalPayload` 排除 release_authority 字段（防止签名递归）

## git-hook conventions

- `proofctl git-hook install` — injects a POSIX sh block into `.git/hooks/pre-commit`;
  rejects any staged `.proofctl/attestations/*.json` file that lacks a `"signature"` field
- `proofctl git-hook uninstall` — removes only the managed block; leaves the rest of the hook intact
- `proofctl git-hook status` — reports whether the proofctl block is present in the hook
- `install` is idempotent; safe to run in `proofctl init` scripts or project onboarding
- The hook is POSIX sh with no external dependencies beyond `git` and `grep`
- For full cryptographic verification at commit time, pair the hook with `require_signed_attestations: true`
  in the policy file (activates release C05 condition)

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
- CI also runs: `domains-lint` job (lints all domains/*/contracts/*.json + metamath smoke test)
- The pre-commit hook at `.git/hooks/pre-commit` runs the same checks locally
- Release workflow: `release.yml` builds proofctl + proofverify for 4 platforms on tag push

## release artifacts

- `.proofctl/STATUS.json` — written by `proofctl release` (always, pass or fail)
- `.proofctl/release-snapshot.json` — written by `proofctl release` on pass only;
  contains per-evidence metadata; consumer repos should read this instead of
  maintaining their own STATUS.json
- Do not write `certified_radius` anywhere — the field is `release_target`
