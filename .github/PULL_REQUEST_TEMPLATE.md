## Summary
<!-- One sentence describing what this PR does -->

## Motivation
<!-- Why is this change needed? Link to the issue if one exists: Closes #N -->

## Changes
<!-- Bullet list of what changed, grouped by package if multiple packages are touched -->

## Testing
<!-- Describe how you tested this. New tests should follow CONTRIBUTING.md:
     security/semantic changes require a failing test first. -->

- [ ] `go build ./...` passes
- [ ] `go vet ./...` passes
- [ ] `gofmt -l .` produces no output
- [ ] `go test -race -timeout 120s ./...` passes
- [ ] New adversarial/exploit inputs added to `testdata/adversarial/` (if applicable)

## Security Invariant Checklist
<!-- Required for any change to internal/kernel/, internal/release/, pkg/protocol/v2/, cmd/proofverify/, or adapters/ -->

- [ ] **Which invariant(s) does this change affect?** (INV-XX or "none")
- [ ] **Does this change add a new trust input?** If yes, describe where it is validated.
- [ ] **What mutation or exploit test covers the invariant?** (function name or "new: TestXxx added")

## General Checklist
- [ ] No hardcoded absolute paths or usernames introduced
- [ ] No third-party dependencies added (`go.sum` unchanged)
- [ ] Error codes use existing constants from `internal/errors`
- [ ] `certified_radius` remains `null` if the release gate has not passed
- [ ] `SECURITY-INVARIANTS.md` updated if a new invariant was added or an existing one changed
