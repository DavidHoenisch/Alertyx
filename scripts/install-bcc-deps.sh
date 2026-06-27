#!/usr/bin/env bash
# Install BCC/libbcc build dependencies for gobpf on Debian/Ubuntu.
set -euo pipefail

sudo apt-get update

PACKAGES=(
  linux-headers-generic
  libelf-dev
  clang
  llvm
  build-essential
)

KERNEL_HEADERS="linux-headers-$(uname -r)"
if apt-cache show "${KERNEL_HEADERS}" >/dev/null 2>&1; then
  PACKAGES+=("${KERNEL_HEADERS}")
fi

if apt-cache show libbpfcc-dev >/dev/null 2>&1; then
  PACKAGES+=(libbpfcc-dev)
elif apt-cache show libbcc-dev >/dev/null 2>&1; then
  PACKAGES+=(libbcc-dev)
else
  echo "Neither libbpfcc-dev nor libbcc-dev is available via apt" >&2
  exit 1
fi

sudo apt-get install -y "${PACKAGES[@]}"
