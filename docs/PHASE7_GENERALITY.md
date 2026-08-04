# Multi-Domain Generality Report

**Date:** 2026-08-04
**Status:** VERIFIED
**Domains verified:** LRAT, Metamath, Lean 4, Coq/Rocq, SMT/Alethe, Isabelle/HOL

---

## Objective

This report confirms that the ProofGraph engine is domain-agnostic. Adding any new
proof domain requires ZERO changes to the core IR, CAS, status machine, or release gate.
All domain-specific logic lives in `adapters/<domain>/` and `domains/<domain>/`.

The machine-readable enforcement is `testdata/adversarial/generality_test.go`:
`TestCore_NoDomainHardcoding` scans `internal/kernel/`, `internal/release/`, and
`pkg/protocol/v2/` for domain identifiers and fails CI if any are found.

---

## Domains Active (2026-08-04)

| Domain | Adapter | Bridge | ContractV2 | Policy v2 | scaffold |
|--------|---------|--------|------------|-----------|----------|
| `cap`      | ✅ | ✅ | — | — | ✅ |
| `weil`     | ✅ | ✅ | ✅ D1–D18 | ✅ | ✅ |
| `lrat`     | ✅ | — | — | — | ✅ |
| `qmd`      | ✅ | — | — | — | ✅ |
| `metamath` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `lean`     | ✅ | ✅ | ✅ | ✅ | ✅ |
| `coq`      | ✅ | ✅ | ✅ | ✅ | ✅ |
| `smt`      | ✅ | ✅ | ✅ | ✅ | ✅ |
| `isabelle` | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## What Was NOT Modified

The following core packages were left unchanged:

| Package | Description |
|---|---|
| `internal/ir` | Claim, Dependency, Evidence, Attestation, Status types |
| `internal/dag` | DAG construction, cycle detection, closure, frontier |
| `internal/cas` | Content-addressed blob store |
| `internal/status` | Status computation (open/blocked/accepted/rejected) |
| `internal/policy` | Release policy evaluation |
| `internal/release` | Release gate (DryRun + Release + 13 conditions) |
| `internal/snapshot` | Immutable, content-addressed ProofGraph snapshots |
| `internal/attestation` | Attestation construction utilities |
| `internal/checker` | Checker protocol and identity pinning |
| `internal/freshness` | Freshness tracking |
| `pkg/protocol` | Public wire types for external checker processes |

No assurance type constants were added or changed.
No status type constants were added or changed.
The 13 Weil release conditions in `conditions.go` were not touched.

---

## What Was Added

New files added for the LRAT domain:

| File | Description |
|---|---|
| `internal/lrat/types.go` | LRAT domain constants and checker identity |
| `adapters/lrat/adapter.go` | Compiles a ProblemSpec into 3-claim ProofGraph IR |
| `policies/lrat-release-v1.json` | Release policy for the LRAT domain |
| `internal/lrat/generality_test.go` | Phase 7 acceptance tests |
| `adapters/lrat/adapter_test.go` | Adapter unit tests |
| `docs/PHASE7_GENERALITY.md` | This report |

---

## Proof Graph Structure (LRAT Domain)

Each LRAT problem compiles into exactly 3 claims:

```
def-<id>-formula  (cnf-formula)
       |
       v
lem-<id>-unsat    (unsat-claim)
       |
       v
thm-<id>-verified (lrat-verified)
```

This is structurally analogous to the Weil proof graph (definitions -> lemmas -> theorem),
using the exact same `ir.Claim` type with the same `DependsOn` dependency wiring.

---

## Key Invariants Verified by Test

The tests in `internal/lrat/generality_test.go` verify:

**1. Same IR types for both domains** (`TestGenerality_IRModelUnchanged`)
Both the Weil adapter and the LRAT adapter produce `ir.Claim`, `ir.EvidenceDescriptor`,
`ir.CheckerIdentity`, and `ir.Attestation` values. All are JSON-serializable and
round-trip correctly from both domains.

**2. Same CAS for both domains** (`TestGenerality_CASWorks`)
LRAT evidence blobs (CNF files and LRAT certificates) store and retrieve via the
same `cas.Store` API. The `cas.Verify` integrity check works identically.

**3. Same DAG for both domains** (`TestGenerality_DAGValidates`)
A DAG built from LRAT claims validates with `dag.Validate()` — same cycle detection,
same dependency resolution logic as the Weil domain.

**4. Same status computation** (`TestGenerality_StatusCompute`)
When a dependency attestation is blocked, `status.Compute` correctly propagates
blocked status to dependent claims — same state machine, same rules.

**5. Same policy engine** (`TestGenerality_PolicyEvaluate`)
`policies/lrat-release-v1.json` is evaluated by `policy.Evaluate` — the same function
used by the Weil domain. Forbidden assurances (ai-review, assumption, shadow-review)
are correctly blocked.

**6. Same release gate** (`TestGenerality_ReleaseGate`)
`release.Gate.DryRun` runs all 13 conditions against LRAT attestations using the
same gate logic. A fully accepted LRAT graph passes.

**7. Same snapshot mechanism** (`TestGenerality_SnapshotDeterministic`)
`snapshot.Take` on an LRAT graph produces a stable, deterministic SelfDigest.
Taking the same snapshot twice yields the same hash.

**8. No core modification** (`TestGenerality_NoCoreModification`)
All imports in the LRAT domain reference the same `internal/ir`, `internal/dag`,
`internal/cas`, `internal/status`, `internal/release`, `internal/snapshot`, and
`internal/policy` packages. No LRAT-specific forks of any core package exist.

---

## Conclusion

The ProofGraph engine is NOT a Weil-specific wrapper.

A second domain (LRAT SAT proof certificates) was connected by adding only:
- A domain types package (`internal/lrat`)
- An adapter (`adapters/lrat`)
- A release policy (`policies/lrat-release-v1.json`)

Zero modifications were made to any core IR, engine, or release gate file.

The engine's generality guarantee holds.
