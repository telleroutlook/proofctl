# Contributing to proofctl

## Governance

**Security and semantic changes require a failing test first.**
Before implementing any change that affects correctness, policy evaluation, trust
boundaries, or resource limits, write a test that fails, then make it pass.
No exceptions. A pull request that adds behavior without a corresponding test will
not be merged.

## Running the Test Suite

```bash
# Build and vet
go build ./...
go vet ./...

# Unit and integration tests (with race detector)
go test -race ./...

# Static analysis
staticcheck ./...

# Integration tests only (requires -tags integration build tag)
go test -tags integration -race ./...
```

All of the above must pass with zero failures before a pull request is opened.

## Adding a New Claim Domain (Adapter)

1. Create a new package under `adapters/<name>/`.
2. Implement a `Compile(src []byte) (*ir.ProofGraph, error)` function.
3. Add a `_test.go` file with at least one round-trip test and one adversarial input test.
4. Register the adapter in `cmd/proofctl/main.go` under `cmdCompile`.
5. Add a policy file under `policies/` if the domain has domain-specific release criteria.
6. Add an entry to the Phase table in `README.md`.

Generality requirement: adapters must produce ProofGraph IR that passes `ir.ProofGraph.Validate()`
and `dag.DAG.Validate()` without special-casing in the engine core.

## Reporting Security Issues

File a GitHub issue with the title prefix `[SECURITY]`. Include:
- A minimal reproducer (proof graph JSON or test case)
- The expected behavior and the observed behavior
- The component affected (CAS, DAG, policy gate, checker runner, IR decoder)

Do not include real credentials, internal network addresses, or proprietary data in issues.

## Code Style

- **English only**: all identifiers, comments, error messages, and documentation must be
  in English. No other language may appear anywhere in the codebase.
- **Stdlib only**: the engine core and all adapters use only the Go standard library.
  No third-party dependencies are permitted.
- **No hardcoded paths**: use relative paths or environment variable defaults.
  Never hardcode an absolute path or a machine-specific username in source files.
- **Fail closed**: when in doubt, return an error rather than silently accepting input.
  The system must never silently degrade to a weaker trust posture.
- **Constants for limits**: resource limits belong in named constants (see `internal/ir/decode.go`),
  never as magic numbers inline in validation logic.
