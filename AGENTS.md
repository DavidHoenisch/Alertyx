# AGENTS.md - Alertyx Development Guide

## Project Overview

Alertyx is a Linux endpoint detection and response (EDR) tool built in Go using eBPF for kernel-level monitoring. It detects suspicious activities mapped to MITRE ATT&CK techniques.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI (cobra)                          │
│              cmd/root.go, monitor.go, hunt.go               │
├─────────────────────────────────────────────────────────────┤
│                     Core Utilities                          │
│         utils/monitor.go, mitigate.go, hunt.go              │
├──────────────────────┬──────────────────────────────────────┤
│   Event Collection   │        Detection Techniques          │
│   events/*.go        │        techs/*.go                    │
│   (eBPF programs)    │        (T#### MITRE mappings)        │
├──────────────────────┴──────────────────────────────────────┤
│                    Analysis Engine                          │
│            analysis/analysis.go, detections.go              │
├─────────────────────────────────────────────────────────────┤
│                  Correlation Engine                         │
│         correlate/correlation.go, search.go                 │
├─────────────────────────────────────────────────────────────┤
│                    Output Formatting                        │
│                    output/output.go                         │
└─────────────────────────────────────────────────────────────┘
```

## Key Packages

| Package | Purpose |
|---------|---------|
| `cmd/` | CLI commands using cobra |
| `events/` | eBPF event collection (exec, open, listen, readline) |
| `techs/` | Detection techniques (MITRE ATT&CK mapped) |
| `analysis/` | Event analysis and detection logic |
| `correlate/` | Cross-event correlation |
| `output/` | Terminal output with colors (aurora) |
| `utils/` | High-level orchestration |
| `common/` | Shared settings |
| `system/` | System information helpers |

## Code Conventions

### Go Style
- Follow standard Go formatting (`gofmt`)
- Use meaningful variable names
- Keep functions focused and small
- Error handling: always check and handle errors explicitly

### eBPF Code (in events/macros.go)
- C code is embedded as Go string constants
- Macros define reusable eBPF helpers
- Current limitation: PPID tracking disabled for kernel compatibility

### Detection Techniques
- Files named `t####.go` for MITRE techniques, `l####.go` for local/custom
- Each technique implements `Technique` interface:
  - `Name() string`
  - `Check() (CheckResult, error)`
  - `Mitigate() error`
  - `Hunt() ([]HuntResult, error)`

## Testing Requirements

### Unit Tests
- Target: 70% code coverage minimum
- Place tests in `*_test.go` files alongside source
- Use table-driven tests where appropriate
- Mock eBPF interactions for unit tests

### Integration Tests
- Require root privileges and kernel with eBPF support
- Use Vagrant VMs for isolated testing environment
- Test actual eBPF program loading and event capture

### Running Tests
```bash
go test ./...                    # All tests
go test -cover ./...             # With coverage
go test -race ./...              # Race detection
```

## Security Considerations

- This tool requires root privileges for eBPF operations
- Detection techniques that modify system state (Mitigate) must be careful
- Never set sensitive file permissions too permissively
- Validate all input before use in eBPF programs

## Progress Tracking

### GitHub Issues
All work is tracked via GitHub Issues with phase labels:
- `phase-1-testing`: Test infrastructure foundation
- `phase-2-bugs`: Critical bug fixes
- `phase-3-modernization`: Library updates (gobpf -> cilium/ebpf)
- `phase-4-features`: New detection capabilities
- `phase-6-operations`: Production readiness

### Priority Labels
- `priority-critical`: Must fix immediately
- `priority-high`: Important for next milestone
- `security`: Security-related issues

### Commands
```bash
gh issue list --state open                    # All open issues
gh issue list --label phase-1-testing         # Phase 1 issues
gh issue view <number>                        # Issue details
```

## Ralph Loops (Autonomous Agent Execution)

Ralph loops enable autonomous agent execution for working through the backlog.

### Scripts Location
`.cursor/ralph-scripts/`

### Quick Start
```bash
# Run a single issue
.cursor/ralph-scripts/ralph-issue.sh <issue-number>
.cursor/ralph-scripts/ralph-loop.sh

# Run all issues in a phase (sequential)
.cursor/ralph-scripts/ralph-phase.sh --phase 1

# Run issues in parallel (4 concurrent agents)
.cursor/ralph-scripts/ralph-parallel.sh --phase 1 -j 4 --pr -y
```

### Default Model
`composer-2.5-fast`

### Parallel Execution
Uses git worktrees for isolation. Each agent gets its own branch (`ralph/$RUN_ID-$issue_num`).

Monitor progress:
```bash
tail -f .ralph/parallel/*/*.log
```

## Building

```bash
go build -o Alertyx .
```

## Dependencies

- `github.com/iovisor/gobpf` - eBPF interaction (migration to cilium/ebpf planned)
- `github.com/spf13/cobra` - CLI framework
- `github.com/logrusorgru/aurora` - Colored output

## Common Tasks

### Adding a New Detection Technique
1. Create `techs/t####.go` or `techs/l####.go`
2. Implement the `Technique` interface
3. Register in `techs/techs.go` `All()` function
4. Add corresponding tests

### Adding a New Event Type
1. Create `events/<type>.go`
2. Define eBPF program as string constant
3. Implement event struct and parsing
4. Add to event collection in `events/events.go`
