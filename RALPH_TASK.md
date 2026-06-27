---
task: "Issue #3: [Phase 1] Set up mutation testing with gremlins"
test_command: "go test -v ./..."
github_issue: 3
---

# Issue #3: [Phase 1] Set up mutation testing with gremlins

**Labels:** phase-1-testing,testing

## Task Description

## Overview
Implement mutation testing to verify test quality beyond simple coverage metrics.

## Why Mutation Testing?
- Coverage can be misleading (100% coverage with weak assertions)
- Mutation testing reveals if tests actually catch bugs
- Critical for security-sensitive detection logic

## Target Packages
| Package | Why |
|---------|-----|
| `techs/*.go` | Detection logic - false negatives are security issues |
| `correlate/search.go` | Search predicates must be exact |
| `analysis/analysis.go` | Detection scoring and deduplication |

## Setup
```bash
go install github.com/go-gremlins/gremlins/cmd/gremlins@latest
gremlins unleash --tags="" ./techs/...
```

## Acceptance Criteria
- [x] gremlins configured and runnable
- [ ] >60% mutation score on `techs` package (initial target)
- [ ] >80% mutation score before Phase 1 complete
- [ ] Mutation testing in CI (on PRs to main)

## References
See ROADMAP.md Section 1.3

## Success Criteria

- [x] gremlins configured and runnable
- [ ] >60% mutation score on `techs` package (initial target)
- [ ] >80% mutation score before Phase 1 complete
- [ ] Mutation testing in CI (on PRs to main)

## Notes

- Read AGENTS.md for coding standards
- Run `go test ./...` before committing
- Update .ralph/progress.md with your work
- When complete, the issue will be closed via PR

