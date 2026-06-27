# Progress Log

This file tracks progress across Ralph iterations. Updated by the agent after each work session.

## Completed Work

### Iteration 1 — Vagrantfile with multi-distro support
- Added `Vagrantfile` with four VM definitions: ubuntu-22 (jammy), ubuntu-24 (noble), fedora-40, arch
- Each VM syncs repo to `/vagrant`, provisions via `test/integration/provision.sh`, and uses VirtualBox with 2 CPU / 2GB RAM
- Added `test/integration/vagrantfile_test.go` validating VM matrix, boxes, synced folder, and provision path
- Added `.vagrant/` to `.gitignore`

### Iteration 2 — provision.sh for BCC setup
- Added `test/integration/provision.sh` with distro-specific package installs for Ubuntu/Debian (apt), Fedora (dnf), and Arch (pacman)
- Installs BCC runtime/dev packages, kernel headers, clang/llvm, and Go 1.22 when the distro package is too old
- Verifies libbcc and kernel headers are present before completing provisioning
- Added `test/integration/provision_test.go` validating shebang, strict mode, multi-distro support, BCC/Go setup, and `bash -n` syntax

### Iteration 3 — harness.go test framework
- Added `test/integration/harness.go` with `Harness` for eBPF load/collect, `ScanEvents` for technique validation, and skip helpers for integration/root guards
- Added build-tag stubs in `harness_build.go` and `harness_integration.go` for `-tags=integration` detection
- Added `harness_test.go` with synthetic event tests for L1002, L1005, and T1098 scanning paths
- Added `harness_integration_test.go` verifying integration build tag wiring

### Iteration 4 — Example test cases for L1002, L1005, T1098
- Added `test/integration/techniques_integration_test.go` with live eBPF integration examples using `Harness.RunAndWait`:
  - L1005: detects writes under `/tmp`
  - L1002: detects non-privileged `/etc/shadow` access via `head` with Open+Exec probes
  - T1098: detects cross-user `authorized_keys` modification (root writing to nobody-owned file)
- Added `test/integration/techniques_test.go` validating example test file structure and technique coverage without requiring `-tags=integration`

### Iteration 5 — Documentation for running integration tests
- Added `test/integration/README.md` covering prerequisites, VM matrix, quick start, per-VM workflows, test commands, harness overview, and troubleshooting
- Added `test/integration/docs_test.go` validating README presence and required sections/commands

## Current Status

All criteria complete. Issue #5 deliverables finished.
