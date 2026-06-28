#!/usr/bin/env bash
# Install Alertyx binary and systemd service for production deployment.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
BIN_DIR="${INSTALL_PREFIX}/bin"
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
SERVICE_NAME="alertyx"
BINARY_NAME="alertyx"
BINARY_PATH="${BIN_DIR}/${BINARY_NAME}"
SERVICE_SOURCE="${SCRIPT_DIR}/alertyx.service"
SERVICE_DEST="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service"

log() {
	echo "[install] $*" >&2
}

require_root() {
	if [[ "${EUID}" -ne 0 ]]; then
		log "must run as root (e.g. sudo $0)"
		exit 1
	fi
}

install_binary() {
	if [[ "${SKIP_BUILD:-}" == "1" && -x "${BINARY_PATH}" ]]; then
		log "using existing binary at ${BINARY_PATH} (SKIP_BUILD=1)"
		return
	fi

	log "building Alertyx from ${REPO_ROOT}"
	tmp_binary="$(mktemp)"
	trap 'rm -f "${tmp_binary}"' RETURN
	(
		cd "${REPO_ROOT}"
		go build -o "${tmp_binary}" .
	)
	install -d -m 0755 "${BIN_DIR}"
	install -m 0755 "${tmp_binary}" "${BINARY_PATH}"
	log "installed binary to ${BINARY_PATH}"
}

install_service() {
	if [[ ! -f "${SERVICE_SOURCE}" ]]; then
		log "missing service file: ${SERVICE_SOURCE}"
		exit 1
	fi
	install -d -m 0755 "${SYSTEMD_UNIT_DIR}"
	install -m 0644 "${SERVICE_SOURCE}" "${SERVICE_DEST}"
	log "installed systemd unit to ${SERVICE_DEST}"
}

enable_service() {
	systemctl daemon-reload
	systemctl enable "${SERVICE_NAME}.service"
	log "enabled ${SERVICE_NAME}.service"
}

start_service() {
	if [[ "${NO_START:-}" == "1" ]]; then
		log "skipping service start (NO_START=1)"
		return
	fi
	if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
		systemctl restart "${SERVICE_NAME}.service"
	else
		systemctl start "${SERVICE_NAME}.service"
	fi
	log "started ${SERVICE_NAME}.service"
}

main() {
	require_root
	install_binary
	install_service
	enable_service
	start_service
	log "installation complete"
}

main "$@"
