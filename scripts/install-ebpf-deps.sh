#!/usr/bin/env bash
# Install eBPF build dependencies for cilium/ebpf on Debian/Ubuntu.
set -euo pipefail

sudo apt-get update

PACKAGES=(
	linux-headers-generic
	libelf-dev
	libbpf-dev
	clang
	llvm
	build-essential
)

KERNEL_HEADERS="linux-headers-$(uname -r)"
if apt-cache show "${KERNEL_HEADERS}" >/dev/null 2>&1; then
	PACKAGES+=("${KERNEL_HEADERS}")
fi

sudo apt-get install -y "${PACKAGES[@]}"
