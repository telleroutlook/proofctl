# ADR-004: Single Release Gate with Explicit Conditions

**Date:** 2026-08-03  
**Amended:** 2026-08-04 (M22 — generalised from Weil-specific to universal + domain-conditional)  
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

---

## Decision

The ProofGraph Engine uses a **single release gate** with **explicit, named conditions**.
The gate is the only code path that may write `STATUS.json`.

### Universal conditions (always evaluated)

```
C01  global-status-accepted       All claims have accepted attestations
C02  assumption-footprint-empty   No claim uses "assumption" assurance
C03  assurances-allowed           All assurances are in the allowed list / not forbidden
C04  replay-consistency           All checker-policy claims have self_digest + freshness fields
```

### Policy-activated conditions (evaluated when the policy field is set)

```
C05  attestation-signatures       All attestations carry a valid Ed25519 signature
                                  (activated by require_signed_attestations: true)
C06  metadata-values              No metadata value falls outside the allowed set
                                  (activated by allowed_metadata_values)
C07  conditional-metadata         Required key present whenever trigger key is found
                                  (activated by conditional_metadata_keys)
C08  replay-mode                  All attestations match the required replay depth
                                  (activated by required_replay_mode)
```

### Domain conditions (one per required_metadata_keys entry)

```
meta:<key>  The key is present and non-empty in at least one attestation
```

Architectural constraints:

1. **DryRun and Release share one check function** (`gate.check`). There is no
   "relaxed" path for dry runs. The only difference is that `Release` writes
   `STATUS.json` and `DryRun` does not.

2. **STATUS.json is written atomically** via temp file + fsync + rename. If the
   write fails, no partial STATUS.json is left on disk.

3. **release_target stays empty** until all conditions pass. There is no
   mechanism to set it to a non-empty value without passing the gate.

4. **Conditions produce structured results** (`ConditionResult{ID, Passed, Blocker}`).
   The CLI prints a condition table showing which conditions passed and failed,
   with machine-readable blocker strings for each failure.

---

## Consequences

- No date pressure or external authority can cause `release_target` to become
  non-empty without all active conditions passing.
- `DryRun` and `Release` using the same check function means that a passing
  `DryRun` guarantees a passing `Release` (modulo STATUS.json write failure).
- A partial release is impossible: `released` is either `false` or `true`.
- The structured condition results are included in both the human CLI output and
  the JSON output of `proofctl release`, enabling automated monitoring.
- Adding a new universal condition requires amending `EvaluateConditions`,
  adding a `ConditionID` constant, adding tests, and amending this ADR.
- Policy-activated conditions (C05–C08) are opt-in and backward-compatible:
  existing policy files without the activating field are unaffected.
- Domain conditions (`meta:<key>`) are data-driven from `required_metadata_keys`
  in the policy JSON — no code changes required for new domains.
