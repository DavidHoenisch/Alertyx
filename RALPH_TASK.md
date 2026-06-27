---
task: "Issue #5: [Phase 1] Set up Vagrant-based integration testing"
test_command: "go test -v ./..."
github_issue: 5
---

# Issue #5: [Phase 1] Set up Vagrant-based integration testing

**Labels:** phase-1-testing,testing,infrastructure

## Task Description

## Overview
Create VM-based integration test environment for testing eBPF programs against real kernels.

## Why VMs?
- eBPF requires real kernel access (can't be mocked)
- Need to test across kernel versions (5.x, 6.x, 7.x)
- Safe isolation for triggering "malicious" behaviors

## Vagrantfile Setup
Test matrix:
- Ubuntu 22.04 (Kernel 5.15) - LTS baseline
- Ubuntu 24.04 (Kernel 6.8) - Current LTS
- Fedora 40 (Kernel 6.8+) - Upstream tracking
- Arch Linux (Kernel 7.x) - Bleeding edge

## Deliverables
- [ ] `Vagrantfile` with multi-distro support
- [ ] `test/integration/provision.sh` for BCC setup
- [ ] `test/integration/harness.go` test framework
- [ ] Example test cases for L1002, L1005, T1098
- [ ] Documentation for running integration tests

## Commands
```bash
vagrant up ubuntu-22
vagrant ssh ubuntu-22 -c "cd /vagrant && sudo go test -tags=integration ./..."
```

## References
See ROADMAP.md Section 1.5

## Success Criteria

- [ ] `Vagrantfile` with multi-distro support
- [ ] `test/integration/provision.sh` for BCC setup
- [ ] `test/integration/harness.go` test framework
- [ ] Example test cases for L1002, L1005, T1098
- [ ] Documentation for running integration tests

## Notes

- Read AGENTS.md for coding standards
- Run `go test ./...` before committing
- Update .ralph/progress.md with your work
- When complete, the issue will be closed via PR

