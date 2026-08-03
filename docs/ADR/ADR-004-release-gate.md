# ADR-004: Single Release Gate with 13 Explicit Conditions

**Date:** 2026-08-03  
**Status:** Accepted  
**Deciders:** proofctl core team

---

## Context

Early versions of the system used a set of ad-hoc manual status fields to track
whether individual claims had been verified. This approach fails at scale for
several reasons:

1. **No single source of truth**: status fields scattered across attestation files
   can become inconsistent with each other.
2. **No enforcement**: a human could set `status: accepted` without running a checker.
3. **No aggregate view**: there was no automated way to determine whether the full
   set of conditions for a release had all been satisfied simultaneously.
4. **Date pressure circumvention**: without a programmatic gate, release decisions
   could be made informally by ignoring individual failing conditions.
5. **No structured reporting**: "something is blocked" is not actionable;
   "C03 fails because shadow-review is forbidden in the policy" is.

The Weil proof program has 18 known defect categories (D1–D18) and requires
13 specific conditions to all pass before the main radius theorem can be certified.
Tracking these manually is error-prone and does not scale.

---

## Decision

The ProofGraph Engine uses a **single release gate** with **13 explicit, named conditions**
(C01–C13). The gate is the only code path that may write `STATUS.json` and set
`certified_radius` to a non-null value.

```
C01  global-status-accepted       All claims have accepted attestations
C02  assumption-footprint-empty   No claim uses "assumption" assurance
C03  assurances-allowed           All assurances are in the allowed list / not forbidden
C04  cap-format-v2-frozen         CAP format version 2 is recorded in attestation metadata
C05  digests-fresh                All attestations record freshness timestamps
C06  path-keys-match              Path A and Path B primitive keys match expected sets
C07  intervals-intersect          Path A/B intersection is non-empty
C08  matrix-reconstructed         Reconstruction matrix digest matches certificate
C09  ldlt-passes                  L-D-L^T factorization checker accepted
C10  odd-sector-passes            Odd sector checker accepted
C11  even-sector-passes           Even sector checker accepted
C12  pivot-radius-ratio           Pivot radius ratio is within bound
C13  replay-consistency           All attestations have self-digest + freshness fields
```

Architectural constraints:

1. **DryRun and Release share one check function** (`gate.check`). There is no
   "relaxed" path for dry runs. The only difference is that `Release` writes
   `STATUS.json` and `DryRun` does not.

2. **STATUS.json is written atomically** via temp file + fsync + rename. If the
   write fails, no partial STATUS.json is left on disk.

3. **certified_radius stays null** until all 13 conditions pass. There is no
   mechanism to set it to a non-null value without passing the gate.

4. **Conditions produce structured results** (`ConditionResult{ID, Passed, Blocker}`).
   The CLI prints a condition table showing which conditions passed and failed,
   with machine-readable blocker strings for each failure.

---

## Consequences

- No date pressure or external authority can cause `certified_radius` to become
  non-null without all 13 conditions passing. The gate is programmatic and
  cannot be "approved around."
- The 13 conditions map directly to the Weil acceptance criteria in
  `docs/WEIL_ACCEPTANCE.md`. Any change to the acceptance criteria requires a
  corresponding change to the condition set and this ADR.
- `DryRun` and `Release` using the same check function means that a passing
  `DryRun` guarantees a passing `Release` (modulo STATUS.json write failure).
  There are no hidden relaxations in the dry-run path.
- A partial release (where some conditions pass and others do not) is impossible:
  `certified_radius` is either null or the full target claim ID.
- The structured condition results (C01–C13) are included in both the human CLI
  output and the JSON output of `proofctl release`, enabling automated monitoring
  and dashboard display of proof progress.
- Adding a new condition requires adding it to the `EvaluateConditions` function,
  the `ConditionID` constants, and this ADR. Removing a condition requires
  explicit justification and an ADR amendment.
