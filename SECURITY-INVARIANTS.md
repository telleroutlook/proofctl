# Security Invariants

This document maps each of the 12 Canvas security invariants to their
production code location and end-to-end test function. A failing test here
is a blocking invariant violation, not a quality issue.

## Invariant Status

| INV | Description | Code Location | Test Function | Status |
|-----|-------------|---------------|---------------|--------|
| INV-01 | No writable PASS/RELEASED fields in v2 checker output | `pkg/protocol/v2/types.go` — CheckerOutputV2 has no Outcome/Assurance field | `TestINV01_NoWritablePassField`, `TestINV01_ObligationVerdictConstants` | ✅ ACTIVE |
| INV-02 | Result must bind full identity closure | `internal/kernel/attestation/attestation.go:Validate` — checks ClaimIdentityDigest | `TestINV09_StalenessOnIdentityChange` (via identity mismatch) | ✅ ACTIVE |
| INV-03 | attestation self-digest recomputed on load | `internal/kernel/attestation/attestation.go:ComputeSelfDigest` + `Validate` | `TestComputeSelfDigest_Format`, mutation fixture `attestation_self_digest_tampered.json` | ✅ ACTIVE |
| INV-04 | Signature verified against policy-authorized key | `internal/kernel/attestation/attestation.go:verifySignature` + `internal/release/conditions.go:checkC05AttestationSignatures` | `TestC05_SignatureVerification` in `gate_coverage_test.go` | ✅ ACTIVE |
| INV-05 | Machine assurance only from runtime backend | `internal/verify/verify.go` — v2 path derives outcome from ObligationResults, never reads Assurance field | `TestINV01_NoWritablePassField` (structural) | ✅ ACTIVE |
| INV-06 | Obligation exact-set enforced | `pkg/protocol/v2/validate.go:ValidateOutput` — OBLIGATION_MISSING/EXTRA/DUPLICATE | `TestINV06_ObligationExactSet_*`, mutation fixtures `v2_missing/extra/duplicate_obligation.json` | ✅ ACTIVE |
| INV-07 | Required evidence failure → whole claim fails | `internal/verify/verify.go:runCheckerAllEvidence` (T-M31-6) + `internal/kernel/derive/derive.go:DeriveClaimState` Rule 3 | `TestINV07_PartialEvidenceFailure_*` | ✅ ACTIVE |
| INV-08 | Dependency at wrong state blocks downstream upgrade | `internal/kernel/derive/derive.go:DeriveClaimState` Rule 2 + dep-state check | `TestINV08_*` in derive_test.go | ✅ ACTIVE |
| INV-09 | Identity closure change → downstream STALE | `internal/kernel/derive/derive.go:PropagateStale` + `DeriveClaimState` Rule 1 | `TestINV09_StalenessOnIdentityChange`, `TestINV09_PropagateStale_DownstreamInvalidated` | ✅ ACTIVE |
| INV-10 | native runtime results cannot reach release | `internal/kernel/derive/derive.go:DeriveClaimState` Rule 6a (T-M34-2) + `internal/release/conditions.go:checkC09NoNativeRuntime` | `TestNativeDevCappedAtLocallyVerified`, `TestNativeDevCappedEvenWithReplayAndManifest`, mutation fixture `v2_native_runtime_in_release.json` | ✅ ACTIVE |
| INV-11 | Release derived from v2 files, never from STATUS.json | `cmd/proofverify/main.go:verifyBundle` — no STATUS.json read | `TestExploit01_V1OutcomeTampered` (v1 rejection) | ✅ ACTIVE |
| INV-12 | Release bundle is self-verifiable offline | `cmd/proofverify/main.go:verifyBundle` — member digest verification + `internal/kernel/bundle/sign.go` | `TestPayloadDigest_ChangeSensitive`, `TestCanonicalPayload_ReleaseAuthorityDoesNotAffectDigest` | ✅ ACTIVE |

## How to add a new invariant

1. Assign the next INV-XX number.
2. Implement the enforcement in `internal/kernel/` (preferred) or the closest fail-closed path.
3. Add at least one test in `testdata/adversarial/` that directly triggers the invariant.
4. Add the row to this table with both code location (file:line) and test function name.
5. CI `release-exploit-suite` job must pass before the PR can merge.

## PR invariant checklist

Every PR that touches `internal/kernel/`, `internal/release/`, `pkg/protocol/v2/`,
`cmd/proofverify/`, or `adapters/` must answer:

- Which invariant does this change affect?
- Does the change add a new trust input? If so, is it validated?
- What mutation or exploit test covers it?
