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

## Troubleshooting

**Service fails to start**

- Confirm the binary exists and is executable: `ls -l /usr/local/bin/alertyx`
- Check journal output: `journalctl -u alertyx.service -n 50 --no-pager`
- Verify eBPF is available on the host and the kernel supports required BPF features

**Permission or capability errors**

- The service requires elevated capabilities for eBPF; see the unit file `CapabilityBoundingSet` and `AmbientCapabilities` settings
- `NoNewPrivileges=no` is required so BPF programs can load

**Install script errors**

- Run as root: `sudo ./deploy/install.sh`
- Ensure Go is installed and on `PATH` when building from source
- Use `SKIP_BUILD=1` only when a working binary is already at the target path
