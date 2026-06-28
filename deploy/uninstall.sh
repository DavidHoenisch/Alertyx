#!/usr/bin/env bash
# Uninstall Alertyx binary and systemd service.
set -euo pipefail

INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
BIN_DIR="${INSTALL_PREFIX}/bin"
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
SERVICE_NAME="alertyx"
BINARY_NAME="alertyx"
BINARY_PATH="${BIN_DIR}/${BINARY_NAME}"
SERVICE_DEST="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service"

log() {
	echo "[uninstall] $*" >&2
}

require_root() {
	if [[ "${EUID}" -ne 0 ]]; then
		log "must run as root (e.g. sudo $0)"
		exit 1
	fi
}

stop_service() {
	if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
		systemctl stop "${SERVICE_NAME}.service"
		log "stopped ${SERVICE_NAME}.service"
	else
		log "${SERVICE_NAME}.service is not running"
	fi
}

disable_service() {
	if systemctl is-enabled --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
		systemctl disable "${SERVICE_NAME}.service"
		log "disabled ${SERVICE_NAME}.service"
	else
		log "${SERVICE_NAME}.service is not enabled"
	fi
}

remove_service_unit() {
	if [[ -f "${SERVICE_DEST}" ]]; then
		rm -f "${SERVICE_DEST}"
		log "removed systemd unit ${SERVICE_DEST}"
	else
		log "systemd unit not found at ${SERVICE_DEST}"
	fi
}

reload_systemd() {
	systemctl daemon-reload
	log "reloaded systemd daemon"
}

remove_binary() {
	if [[ "${KEEP_BINARY:-}" == "1" ]]; then
		log "skipping binary removal (KEEP_BINARY=1)"
		return
	fi
	if [[ -f "${BINARY_PATH}" ]]; then
		rm -f "${BINARY_PATH}"
		log "removed binary ${BINARY_PATH}"
	else
		log "binary not found at ${BINARY_PATH}"
	fi
}

main() {
	require_root
	stop_service
	disable_service
	remove_service_unit
	reload_systemd
	remove_binary
	log "uninstallation complete"
}

main "$@"
