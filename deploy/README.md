# Production Deployment

Run Alertyx as a systemd service for continuous eBPF-based monitoring on Linux hosts.

## Prerequisites

- Linux with eBPF support (kernel 5.8+ recommended for `CAP_BPF`)
- Root privileges for installation and service operation
- `systemd` as the init system
- Go toolchain when building from source (the install script runs `go build`)
- C compiler and kernel headers for eBPF program compilation

## Quick Install

From the repository root:

```bash
sudo ./deploy/install.sh
```

This builds the binary, installs it to `/usr/local/bin/alertyx`, installs the systemd unit to `/etc/systemd/system/alertyx.service`, reloads systemd, enables the service, and starts it.

## Install Script Options

The install script supports environment overrides:

| Variable | Default | Description |
|----------|---------|-------------|
| `INSTALL_PREFIX` | `/usr/local` | Base directory for the binary (`$INSTALL_PREFIX/bin/alertyx`) |
| `SYSTEMD_UNIT_DIR` | `/etc/systemd/system` | Directory for the systemd unit file |
| `SKIP_BUILD` | unset | Set to `1` to skip `go build` when the binary already exists |
| `NO_START` | unset | Set to `1` to install and enable without starting the service |

Example: install without starting immediately:

```bash
sudo NO_START=1 ./deploy/install.sh
```

## Manual Installation

1. Build and install the binary:

   ```bash
   go build -o /usr/local/bin/alertyx .
   chmod 0755 /usr/local/bin/alertyx
   ```

2. Install the systemd unit:

   ```bash
   sudo install -m 0644 deploy/alertyx.service /etc/systemd/system/alertyx.service
   ```

3. Enable and start the service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable alertyx.service
   sudo systemctl start alertyx.service
   ```

## Uninstall

From the repository root:

```bash
sudo ./deploy/uninstall.sh
```

This stops and disables the service, removes the unit file, reloads systemd, and removes `/usr/local/bin/alertyx`.

Uninstall script options:

| Variable | Default | Description |
|----------|---------|-------------|
| `INSTALL_PREFIX` | `/usr/local` | Must match the prefix used during install |
| `SYSTEMD_UNIT_DIR` | `/etc/systemd/system` | Must match the unit directory used during install |
| `KEEP_BINARY` | unset | Set to `1` to remove the service but leave the binary |

Example: remove the service but keep the binary:

```bash
sudo KEEP_BINARY=1 ./deploy/uninstall.sh
```

## Service Management

Check service status:

```bash
sudo systemctl status alertyx.service
```

Restart after configuration or binary updates:

```bash
sudo systemctl restart alertyx.service
```

View logs in the journal:

```bash
journalctl -u alertyx.service -f
```

The unit runs `alertyx monitor --syslog` and sends stdout/stderr to the journal with identifier `alertyx`.

## Installed Files

| Path | Description |
|------|-------------|
| `/usr/local/bin/alertyx` | Alertyx binary (default install path) |
| `/etc/systemd/system/alertyx.service` | systemd unit file |
| `deploy/alertyx.service` | Source unit file in the repository |
| `deploy/install.sh` | Automated install script |
| `deploy/uninstall.sh` | Automated uninstall script |

## Resource Limits

The bundled unit file sets `MemoryMax=512M` and `CPUQuota=50%`. Edit `/etc/systemd/system/alertyx.service` and run `sudo systemctl daemon-reload` before restarting if you need different limits.

## Capability Requirements

Alertyx loads eBPF programs into the kernel for continuous monitoring. The bundled systemd unit grants the minimum Linux capabilities needed for that workload instead of running as unrestricted root.

The unit file sets both `CapabilityBoundingSet` and `AmbientCapabilities` to the same four capabilities so the service process inherits them at start:

| Capability | Purpose |
|------------|---------|
| `CAP_BPF` | Load, attach, and manage BPF programs and maps (kernel 5.8+) |
| `CAP_PERFMON` | Attach tracing and perf-related BPF programs (tracepoints, kprobes) |
| `CAP_SYS_ADMIN` | Fallback for pre-5.8 kernels and BPF operations not covered by `CAP_BPF` alone |
| `CAP_SYS_RESOURCE` | Raise locked-memory limits (`RLIMIT_MEMLOCK`) for BPF map allocation |

### Why each capability is required

**`CAP_BPF`** — Primary eBPF privilege on modern kernels. Without it, the monitor cannot load the exec, open, listen, or readline BPF programs that drive detection.

**`CAP_PERFMON`** — Required alongside `CAP_BPF` for attaching many tracing-oriented BPF program types used by the monitor.

**`CAP_SYS_ADMIN`** — Needed when `CAP_BPF` is unavailable (kernels before 5.8) and for some auxiliary operations such as accessing trace infrastructure. Keeping it in the bounding set preserves compatibility across kernel versions.

**`CAP_SYS_RESOURCE`** — BPF maps consume locked kernel memory. This capability allows the process to request sufficient `RLIMIT_MEMLOCK`; without it, program load often fails with memory allocation errors.

### Privilege and hardening settings

**`NoNewPrivileges=no`** — Must remain disabled. Setting `NoNewPrivileges=yes` prevents the process from acquiring the ambient capabilities needed to load BPF programs, causing the service to fail at startup.

**`CapabilityBoundingSet` vs `AmbientCapabilities`** — The bounding set defines the maximum capability set the service may ever use. Ambient capabilities are passed to the `ExecStart` process so the unprivileged service user context still receives the BPF-related caps at launch.

### Verifying capabilities

Inspect the effective unit configuration:

```bash
systemctl show alertyx.service -p CapabilityBoundingSet -p AmbientCapabilities -p NoNewPrivileges
```

If capability errors appear in the journal, confirm the host kernel is 5.8 or newer (for `CAP_BPF`) and that the installed unit matches `deploy/alertyx.service`.

## Troubleshooting

**Service fails to start**

- Confirm the binary exists and is executable: `ls -l /usr/local/bin/alertyx`
- Check journal output: `journalctl -u alertyx.service -n 50 --no-pager`
- Verify eBPF is available on the host and the kernel supports required BPF features

**Permission or capability errors**

- See [Capability Requirements](#capability-requirements) for the purpose of each required capability
- Confirm the running unit includes `CapabilityBoundingSet` and `AmbientCapabilities` with all four caps
- Verify `NoNewPrivileges=no` in the unit file
- On kernels before 5.8, ensure `CAP_SYS_ADMIN` is present because `CAP_BPF` is not available

**Install script errors**

- Run as root: `sudo ./deploy/install.sh`
- Ensure Go is installed and on `PATH` when building from source
- Use `SKIP_BUILD=1` only when a working binary is already at the target path
