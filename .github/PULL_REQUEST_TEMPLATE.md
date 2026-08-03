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
- [ ] New adversarial inputs added to `testdata/adversarial/` (if applicable)

## Checklist
- [ ] No hardcoded absolute paths or usernames introduced
- [ ] No third-party dependencies added (`go.sum` unchanged)
- [ ] Error codes use existing constants from `internal/errors`
- [ ] Resource limits use named constants (no magic numbers)
- [ ] `certified_radius` remains `null` if the release gate has not passed
