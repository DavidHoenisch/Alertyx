---
task: "Issue #1: [Phase 1] Set up unit test infrastructure with 70% coverage target"
test_command: "go test -v ./..."
github_issue: 1
---

# Issue #1: [Phase 1] Set up unit test infrastructure with 70% coverage target

**Labels:** phase-1-testing,priority-critical,testing

## Task Description

## Overview
Establish baseline test coverage for core packages before making any code changes.

## Target Packages (Priority Order)
| Package | Priority | Key Functions to Test |
|---------|----------|----------------------|
| `events` | Critical | `CStr()`, `WriteEventData()`, event `Write()` methods |
| `techs` | Critical | All `Scan()` methods, `Name()` returns |
| `correlate` | High | `search()`, `findUid()`, `findPid()`, `EventType()` |
| `analysis` | High | `processTechs()`, `isDetectionDupe()` |
| `output` | Medium | `IsIgnored()`, level routing |

## Acceptance Criteria
- [x] 70%+ coverage on `events` package
- [x] 70%+ coverage on `techs` package
- [ ] All tests pass with `go test ./...`
- [ ] Coverage report generated

## References
See ROADMAP.md Section 1.1

## Success Criteria

- [x] 70%+ coverage on `events` package
- [x] 70%+ coverage on `techs` package
- [ ] All tests pass with `go test ./...`
- [ ] Coverage report generated

## Notes

- Read AGENTS.md for coding standards
- Run `go test ./...` before committing
- Update .ralph/progress.md with your work
- When complete, the issue will be closed via PR

