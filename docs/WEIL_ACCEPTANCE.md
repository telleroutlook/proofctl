# Weil Acceptance Criteria

## Overview

This document defines the machine-checkable exit criteria for the Weil proof
program and the release conditions for the main radius theorem
`thm-main-radius-030`. It maps the Weil D1–D18 defect catalogue to specific
claim IDs and checker requirements, and defines what "shadow mode" means.

## Defect Catalogue: D1–D18

The following table maps each Weil defect to its claim ID in the ProofGraph,
the checker obligation, and the minimum assurance type required.
This table is authoritative — `internal/weil/defects.go` and `domains/weil/contracts/`
must stay in sync with it.

| Defect | Claim ID                     | Description                                                      | Min Assurance       |
|--------|------------------------------|------------------------------------------------------------------|---------------------|
| D1     | `lem-d1-normalization`       | Input primitives normalization verified by checker               | `deterministic-cap` |
| D2     | `lem-d2-weil-reduction`      | Weil explicit formula reduction step formally verified           | `deterministic-cap` |
| D3     | `lem-d3-legendre`            | Legendre symbol computation independently checked                | `deterministic-cap` |
| D4     | `lem-d4-kernel-bound`        | Kernel bound: expected primitive set fully matched               | `deterministic-cap` |
| D5     | `lem-d5-log-moments`         | Log-moment integrals verified with frozen parameter set          | `deterministic-cap` |
| D6     | `lem-path-a-primitives`      | Path A primitive integral set complete and verified              | `deterministic-cap` |
| D7     | `lem-path-b-primitives`      | Path B primitive integral set complete and verified              | `deterministic-cap` |
| D8     | `lem-ab-intersection`        | Path A∩B non-empty; common primitives jointly verified           | `deterministic-cap` |
| D9     | `lem-matrix-reconstruction`  | Matrix reconstruction checker-confirmed against certificate      | `deterministic-cap` |
| D10    | `lem-interval-ldlt`          | Rational interval LDLT decomposition verified                    | `deterministic-cap` |
| D11    | `lem-d11-odd-sector`         | Odd sector integrals verified by checker                         | `deterministic-cap` |
| D12    | `lem-d12-even-sector`        | Even sector integrals verified by checker                        | `deterministic-cap` |
| D13    | `lem-d13-sector-union`       | Odd+even sector union jointly verified, full range covered       | `deterministic-cap` |
| D14    | `lem-d14-path-a-remainder`   | Path A remainder bound verified by approved method               | `deterministic-cap` |
| D15    | `lem-d15-path-b-remainder`   | Path B remainder bound independently verified (different method) | `deterministic-cap` |
| D16    | `lem-d16-independence`       | Path A/B machine-verified: distinct checker digests, no shared forbidden artifacts | `deterministic-cap` |
| D17    | `lem-d17-enclosure`          | Final interval enclosure confirmed; radius lower bound holds     | `deterministic-cap` |
| D18    | `thm-main-radius-030`        | Main theorem: certified radius ≥ 0.30; all proof obligations closed | `deterministic-cap` |

Each defect has a corresponding `ContractV2` in `domains/weil/contracts/d<N>-*.json`.
All 18 contracts pass `proofctl contract lint`.

## Release Conditions for `thm-main-radius-030`

The claim `thm-main-radius-030` is the main radius theorem. It may be released
(i.e., `certified_radius` set to a non-null value) only when **all** of the
following 13 conditions are satisfied:

1. `def-frozen-model` is accepted with assurance `formal-kernel` or
   `independent-review`.
2. `lem-d1-normalization` is accepted with assurance `formal-kernel`.
3. `lem-d2-weil-reduction` is accepted with assurance `formal-kernel`.
4. `lem-d3-legendre` is accepted with assurance `formal-kernel`.
5. `lem-d4-kernel-bound` is accepted with assurance `formal-kernel`.
6. `lem-d5-log-moments` is accepted with assurance `deterministic-cap` or
   stronger.
7. `lem-path-a-primitives` is accepted with assurance `formal-kernel` or
   `deterministic-cap`.
8. `lem-path-b-primitives` is accepted with assurance `formal-kernel` or
   `deterministic-cap`.
9. `lem-ab-intersection` is accepted with assurance `formal-kernel`.
10. `lem-matrix-reconstruction` is accepted with assurance `deterministic-cap`
    or stronger.
11. `lem-interval-ldlt` is accepted with assurance `exact-replay` or stronger.
12. `thm-main-radius-030` itself is accepted with assurance `formal-kernel`.
13. No attestation in the transitive closure uses `ai-review` or `assumption`.

The release gate enforces these conditions programmatically via the policy file
`policies/weil-release-v1.json`. A human sign-off (separate from the automated
gate) is required before any public announcement of the certified radius.

## Shadow Mode

"Shadow mode" is an operational mode in which the proofctl release gate is run
against the full claim graph but its outcome is **not** used to gate any
external action. In shadow mode:

- All checkers run normally and produce attestations.
- The release gate evaluation runs and produces a STATUS.json.
- The `released: false` field is set regardless of the evaluation result.
- The `certified_radius` field remains `null`.
- Blockers are logged and surfaced to the proof team but do not halt work.

Shadow mode is used during the development phase to:
1. Measure how many claims pass the release criteria before the full proof is
   complete.
2. Detect regressions in previously accepted claims.
3. Validate that checker infrastructure works end-to-end before real release.
4. Generate metrics for the proof progress dashboard.

Shadow mode is **not** a weakened trust mode. All digest, freshness, and
assurance checks run at full strength. The only difference is that a shadow-mode
STATUS.json does not trigger downstream release actions.

To run in shadow mode:

```
proofctl release --shadow
```

Shadow mode is exited (and real release becomes possible) only when:
- All 13 release conditions above are satisfied.
- A human reviewer approves the release in the designated sign-off channel.
- The release gate is run in non-shadow mode with the approved policy version.

## Claim Dependency Graph (Summary)

```
def-frozen-model
  └── lem-d1-normalization
        └── lem-d2-weil-reduction
              ├── lem-d3-legendre
              ├── lem-d4-kernel-bound
              └── lem-d5-log-moments
                    ├── lem-path-a-primitives
                    ├── lem-path-b-primitives
                    │     └── lem-ab-intersection
                    ├── lem-matrix-reconstruction
                    └── lem-interval-ldlt
                          └── thm-main-radius-030
```

This is a summary; the authoritative dependency graph is the compiled
ProofGraph IR, not this diagram.

## Checker Assignment

| Claim                      | Checker                          | Runtime |
|----------------------------|----------------------------------|---------|
| `def-frozen-model`         | `independent-review-checker`     | native  |
| `lem-d1-normalization`     | `lean4-kernel-checker`           | oci     |
| `lem-d2-weil-reduction`    | `lean4-kernel-checker`           | oci     |
| `lem-d3-legendre`          | `lean4-kernel-checker`           | oci     |
| `lem-d4-kernel-bound`      | `lean4-kernel-checker`           | oci     |
| `lem-d5-log-moments`       | `deterministic-compute-checker`  | wasi    |
| `lem-path-a-primitives`    | `lean4-kernel-checker`           | oci     |
| `lem-path-b-primitives`    | `lean4-kernel-checker`           | oci     |
| `lem-ab-intersection`      | `lean4-kernel-checker`           | oci     |
| `lem-matrix-reconstruction`| `deterministic-compute-checker`  | wasi    |
| `lem-interval-ldlt`        | `interval-replay-checker`        | wasi    |
| `thm-main-radius-030`      | `lean4-kernel-checker`           | oci     |

All release checkers must have `network: "none"` in their `CheckerIdentity`.
