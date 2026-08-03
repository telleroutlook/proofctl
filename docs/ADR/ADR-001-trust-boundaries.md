# ADR-001: Trust Boundaries and Permission Model

**Date:** 2026-08-03  
**Status:** Accepted  
**Deciders:** proofctl core team

---

## Context

The ProofGraph Engine manages mathematical proof artifacts that, once certified, may carry
significant downstream consequences (e.g., software release decisions, published radius bounds).
Multiple actors interact with the system: AI-assisted reviewers, automated checkers, human
mathematicians, and the release gate itself.

The key question is: **who has certification authority, and who does not?**

Without an explicit trust hierarchy, the following risks arise:

- An AI reviewer could produce an attestation that superficially resembles a formal proof
  verification, causing the release gate to pass incorrectly.
- A generator script could write an attestation file claiming `formal-kernel` assurance
  without having run a kernel checker.
- A malicious or buggy adapter could silently downgrade an existing accepted attestation.

The system must be fail-closed: an ambiguous or missing attestation must block release,
not permit it.

---

## Decision

We adopt a **5-tier trust hierarchy** in which each tier can only act within its
designated scope:

```
Tier 1: Generator / AI
  - Produces claim graph source files (graph.json)
  - May produce shadow attestations (assurance: shadow-review)
  - Has NO certification authority

Tier 2: Checker
  - A pinned, content-addressed checker binary
  - Produces attestations with a specific assurance type
  - Authority limited to the assurance type it is approved for

Tier 3: ProofGraph IR
  - The compiled, validated claim graph
  - Authoritative record of claim structure and dependencies

Tier 4: Release Gate
  - Evaluates all 13 conditions against the ProofGraph + attestations
  - Fail-closed: any missing or forbidden assurance blocks release
  - Only the gate may write STATUS.json

Tier 5: STATUS.json
  - Written atomically by the release gate on successful pass
  - certified_radius is non-null only when all 13 conditions pass
```

AI review maps specifically to the `ai-review` assurance type. The release policy for
`thm-main-radius-030` places `ai-review` in the `forbidden_assurances` list. This means
an AI review attestation can never satisfy the release requirement for the main theorem.
The same restriction applies to `assumption` and `shadow-review`.

The `shadow-review` assurance is reserved for the Weil shadow adapter. It signals that
the attestation was generated synthetically (not by a real checker) and explicitly cannot
satisfy any release policy requirement.

---

## Consequences

- AI-assisted proof review is a **development tool**, not a certification path.
  The `ai-review` assurance type must appear in `forbidden_assurances` for all
  formal release policies.
- The `assumption` assurance type is similarly forbidden: it exists to mark unverified
  axioms during development, and must be cleared before release.
- A generator or AI that creates a fraudulent attestation with `formal-kernel` assurance
  is a security threat handled by the content-addressed checker identity: the attestation's
  `checker.checker_digest` must match a pinned, reviewed binary.
- The 5-tier model makes it explicit that **no single tier can bypass the tier above it**
  without producing a detectable policy violation.
- The gate's fail-closed posture means that `certified_radius` remains `null` until
  all 13 conditions are satisfied — no partial or probabilistic release is possible.
