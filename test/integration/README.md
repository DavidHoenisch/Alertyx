# Alertyx Integration Tests

Integration tests exercise real eBPF programs against live kernels inside Vagrant VMs. They cannot run on the host without root and a compatible BCC setup; the VM matrix provides isolated, reproducible kernel coverage.

## Prerequisites

- [Vagrant](https://www.vagrantup.com/) 2.x
- [VirtualBox](https://www.virtualbox.org/) (default provider) or another Vagrant-compatible hypervisor
- Enough disk and RAM for at least one VM (2 GB RAM, 2 vCPUs per VM)

Unit tests that validate the integration harness run on the host without VMs:

```bash
go test ./test/integration/...
```

## VM Test Matrix

| VM name     | Distro           | Typical kernel | Purpose              |
|-------------|------------------|----------------|----------------------|
| `ubuntu-22` | Ubuntu 22.04 LTS | 5.15           | LTS baseline         |
| `ubuntu-24` | Ubuntu 24.04 LTS | 6.8            | Current LTS          |
| `fedora-40` | Fedora 40        | 6.8+           | Upstream tracking    |
| `arch`      | Arch Linux       | 7.x            | Bleeding edge        |

`ubuntu-22` is the primary VM (`vagrant up` without a name targets it).

Provisioning installs BCC, kernel headers, clang/llvm, and Go 1.22+ via `test/integration/provision.sh`.

## Quick Start

Start the default VM and run all integration tests:

```bash
vagrant up ubuntu-22
vagrant ssh ubuntu-22 -c "cd /vagrant && sudo go test -tags=integration ./..."
```

Run only the integration package:

```bash
vagrant ssh ubuntu-22 -c "cd /vagrant && sudo go test -tags=integration -v ./test/integration/..."
```

## Working with VMs

Bring up a specific distro:

```bash
vagrant up ubuntu-24
vagrant up fedora-40
vagrant up arch
```

SSH into a running VM:

```bash
vagrant ssh ubuntu-22
```

Inside the VM, the repository is mounted at `/vagrant`:

```bash
cd /vagrant
sudo go test -tags=integration -v ./test/integration/...
```

Rebuild or reprovision after changing `provision.sh`:

```bash
vagrant provision ubuntu-22
```

Destroy a VM when finished:

```bash
vagrant destroy ubuntu-22
```

## Running Tests

Integration tests are gated by the `integration` build tag and require root inside the VM (eBPF loading).

| Command | Where | Notes |
|---------|-------|-------|
| `go test ./test/integration/...` | Host or VM | Harness/unit validation; no eBPF |
| `sudo go test -tags=integration ./test/integration/...` | VM | Live eBPF technique tests |
| `sudo go test -tags=integration -run TestIntegrationL1005 ./test/integration/...` | VM | Single example test |

Example technique tests (require `-tags=integration` and root):

- `TestIntegrationL1005DetectsTmpWrite` — writes under `/tmp`
- `TestIntegrationL1002DetectsShadowAccess` — non-privileged `/etc/shadow` read
- `TestIntegrationT1098DetectsCrossUserAuthorizedKeysWrite` — cross-user `authorized_keys` modification

## Test Framework

`test/integration/harness.go` provides:

- `NewHarness(t)` — loads eBPF probes and collects events
- `Harness.RunAndWait` — runs a trigger action and waits for a technique finding
- `ScanEvents` — scans collected events against techniques (used in unit tests)
- `SkipUnlessIntegration` / `SkipUnlessRoot` — guard helpers for live tests

Files with `//go:build integration` compile only when `-tags=integration` is set.

## Troubleshooting

**VM fails to provision**

- Ensure VirtualBox kernel modules are loaded on the host.
- Run `vagrant provision <vm-name>` and inspect output from `provision.sh`.
- Confirm kernel headers match the running kernel inside the VM.

**Tests skip with "eBPF requires root"**

- Prefix commands with `sudo` inside the VM.

**Tests skip with "rebuild with -tags=integration"**

- Pass `-tags=integration` to `go test`.

**BCC or probe load errors**

- Reprovision the VM: `vagrant provision <vm-name>`.
- Compare behavior across the matrix (especially `ubuntu-22` vs `arch`) to isolate kernel-specific issues.

**Slow first run**

- Initial `vagrant up` downloads the box image and installs packages; subsequent runs are faster.

## Related Files

- `Vagrantfile` — multi-distro VM definitions
- `test/integration/provision.sh` — BCC and Go setup per distro
- `test/integration/harness.go` — shared test harness
- `test/integration/techniques_integration_test.go` — live technique examples
