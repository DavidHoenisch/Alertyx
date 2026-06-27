---
task: "Issue #4: [Phase 1] Implement CRAP analysis baseline"
test_command: "go test -v ./..."
github_issue: 4
---

# Issue #4: [Phase 1] Implement CRAP analysis baseline

**Labels:** phase-1-testing,testing

## Task Description

## Overview
Establish CRAP (Change Risk Anti-Patterns) analysis to identify high-risk, undertested code.

## Formula
`CRAP(m) = complexity(m)^2 * (1 - coverage(m)/100)^3 + complexity(m)`

## Interpretation
| CRAP Score | Risk Level | Action |
|------------|------------|--------|
| < 5 | Low | Acceptable |
| 5-30 | Medium | Consider refactoring or adding tests |
| > 30 | High | Priority refactor |

## Suspected High-CRAP Functions
- `events/events.go:readEvents()` - complex state machine
- `utils/monitor.go:AlertyxMonitor()` - large select loop
- `analysis/analysis.go:processTechs()` - detection pipeline
- `correlate/correlation.go:Summarize()` - event filtering

## Tools
```bash
go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
gocyclo -over 10 .
go test -coverprofile=coverage.out ./...
```

## Acceptance Criteria
- [x] gocyclo baseline documented
- [x] Coverage baseline documented
- [x] High-CRAP functions identified and tracked
- [x] Refactoring plan for functions with CRAP > 30

## References
See ROADMAP.md Section 1.4

## Success Criteria

- [x] gocyclo baseline documented
- [x] Coverage baseline documented
- [x] High-CRAP functions identified and tracked
- [x] Refactoring plan for functions with CRAP > 30

## Notes

- Read AGENTS.md for coding standards
- Run `go test ./...` before committing
- Update .ralph/progress.md with your work
- When complete, the issue will be closed via PR

