#!/usr/bin/env bash
# Runs integration tests across the Vagrant kernel matrix (5.x, 6.x, 7.x).
#
# Usage:
#   ./scripts/test-kernel-matrix.sh              # all VMs
#   ./scripts/test-kernel-matrix.sh ubuntu-22    # single VM

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VMS=(ubuntu-22 ubuntu-24 fedora-40 arch)
INTEGRATION_CMD='cd /vagrant && sudo go test -tags=integration -v ./test/integration/...'

log() {
	echo "[kernel-matrix] $*" >&2
}

require_vagrant() {
	if ! command -v vagrant >/dev/null 2>&1; then
		log "vagrant not found; install Vagrant to run the kernel matrix"
		exit 1
	fi
}

run_vm() {
	local vm="$1"
	log "bringing up $vm"
	vagrant up "$vm" --provision
	log "running integration tests on $vm"
	vagrant ssh "$vm" -c "$INTEGRATION_CMD"
	log "passed on $vm"
}

main() {
	require_vagrant

	local targets=()
	if [[ $# -gt 0 ]]; then
		targets=("$@")
	else
		targets=("${VMS[@]}")
	fi

	for vm in "${targets[@]}"; do
		run_vm "$vm"
	done

	log "kernel matrix complete (${#targets[@]} VM(s))"
}

main "$@"
