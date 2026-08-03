# ADR-002: Content-Addressed Identity for All Proof Artifacts

**Date:** 2026-08-03  
**Status:** Accepted  
**Deciders:** proofctl core team

---

## Context

Proof artifacts — evidence files, checker binaries, schemas, and attestations — must
be **immutable** once created. Mathematical proof requires that the exact bytes used
during verification can be reproduced and audited at any future time.

Mutable identifiers (file paths, version strings, timestamps) are insufficient because:

- A file at a given path can be replaced without changing the path.
- A version string ("v1.2") can be attached to different content over time.
- Timestamps can be forged or skewed across machines.
- A "latest" pointer always refers to a moving target.

The ProofGraph Engine handles multiple artifact types that must all be immutable:

1. **Evidence files** — input data used by checkers
2. **Checker binaries** — the programs that produce attestations
3. **JSON schemas** — the wire format that checkers must satisfy
4. **Attestations** — the verification records themselves

If any of these can mutate silently, the entire verification chain is compromised.

---

## Decision

All proof artifacts are identified by their **sha256 digest and byte size**, not by
their file path or logical name.

```
Canonical identity: sha256:<64-hex-chars>  +  size_bytes
Path hint: advisory only, ignored for equality comparisons
```

Specific rules:

1. **Evidence** (`EvidenceDescriptor`) is identified by `digest` + `size`. The
   `path_hint` field is present for human readability but is explicitly marked
   advisory. Two evidence descriptors are equal iff their digest and size match.

2. **Checker binaries** (`CheckerIdentity`) carry `checker_digest` and `schema_digest`.
   A checker is considered the same checker iff both digests match. Protocol version
   and runtime are additional constraints, not substitutes for digest identity.

3. **Attestations** carry a `self_digest` field computed over all other fields
   (with `self_digest` zeroed). This makes the attestation tamper-evident:
   any change to any field invalidates the self-digest.

4. The **CAS (content-addressed storage)** stores blobs under
   `.proofctl/cas/sha256/<prefix>/<suffix>`, where prefix+suffix = the 64-char
   hex digest. There is no mapping from path to blob; the digest is the only key.

5. Any content change — even a single byte — produces a different digest and is
   treated as a **cache miss**. There is no concept of "close enough" or
   "same version, different build."

---

## Consequences

- **Cache invalidation is automatic**: changing any input file, checker, or schema
  produces a new digest and forces re-verification. There is no manual cache flush.
- **Path_hint is advisory**: moving a file does not change its identity. The engine
  never uses `path_hint` to locate blobs — it uses `digest`.
- **Reproducibility is verifiable**: given a graph, its attestations, and the
  CAS blobs referenced by their digests, any reviewer can independently recompute
  the same attestations from scratch.
- **Storage grows monotonically**: old attestation versions are retained by digest.
  Garbage collection (if ever needed) requires an explicit audit of which digests
  are still reachable.
- **Self-digest on attestations** means that an attestation file that has been
  tampered with (e.g., to change `outcome` from `blocked` to `accepted`) will
  fail a freshness / self-digest check at the release gate.
- The `certified_radius` value in STATUS.json is only stable as long as the
  digests it was computed from remain accessible in the CAS.
