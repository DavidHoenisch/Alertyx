---
task: "Issue #2: [Phase 1] Implement fuzz testing for event parsing"
test_command: "go test -v ./..."
github_issue: 2
---

# Issue #2: [Phase 1] Implement fuzz testing for event parsing

**Labels:** phase-1-testing,security,testing

## Task Description

## Overview
Implement fuzz testing for code that parses untrusted kernel data.

## Target Areas
- `events/generics.go` - `WriteEventData()` binary parsing
- `events/events.go` - `CStr()` C string conversion
- `correlate/search.go` - search functions

## Implementation
Use Go's native fuzzing (Go 1.18+):

```go
func FuzzCStr(f *testing.F) {
    f.Add([]byte("normal\x00string"))
    f.Add([]byte{0x00})
    f.Add([]byte{})
    f.Add(make([]byte, 256))
    
    f.Fuzz(func(t *testing.T, data []byte) {
        _ = CStr(data) // should never panic
    })
}
```

## Acceptance Criteria
- [x] Fuzz tests for `CStr()`
- [x] Fuzz tests for `WriteEventData()`
- [x] No panics found during fuzz runs
- [ ] Fuzz tests integrated into CI (time-limited)

## References
See ROADMAP.md Section 1.2

## Success Criteria

- [x] Fuzz tests for `CStr()`
- [x] Fuzz tests for `WriteEventData()`
- [x] No panics found during fuzz runs
- [ ] Fuzz tests integrated into CI (time-limited)

## Notes

- Read AGENTS.md for coding standards
- Run `go test ./...` before committing
- Update .ralph/progress.md with your work
- When complete, the issue will be closed via PR

