#!/usr/bin/env bash
# Provisions Vagrant VMs with BCC, kernel headers, and Go for Alertyx integration tests.

set -euo pipefail

GO_VERSION="1.22.12"

log() {
	echo "[provision] $*" >&2
}

require_os_release() {
	if [[ ! -f /etc/os-release ]]; then
		log "missing /etc/os-release"
		exit 1
	fi
	# shellcheck disable=SC1091
	source /etc/os-release
}

install_apt_packages() {
	log "installing BCC dependencies via apt (${ID})"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y \
		linux-headers-"$(uname -r)" \
		libbcc-dev \
		libbpf-dev \
		clang \
		llvm \
		build-essential \
		curl \
		git \
		ca-certificates
}

install_dnf_packages() {
	log "installing BCC dependencies via dnf (${ID})"
	dnf install -y \
		kernel-devel \
		bcc-tools \
		bcc-devel \
		libbpf-devel \
		clang \
		llvm \
		gcc \
		curl \
		git \
		ca-certificates
}

install_pacman_packages() {
	log "installing BCC dependencies via pacman (${ID})"
	pacman -Sy --noconfirm \
		base-devel \
		bcc \
		bpf \
		linux-headers \
		clang \
		llvm \
		curl \
		git \
		ca-certificates
}

install_distro_packages() {
	case "${ID:-}" in
	ubuntu | debian)
		install_apt_packages
		;;
	fedora)
		install_dnf_packages
		;;
	arch)
		install_pacman_packages
		;;
	*)
		log "unsupported distro: ${ID:-unknown}"
		exit 1
		;;
	esac
}

go_is_sufficient() {
	if ! command -v go >/dev/null 2>&1; then
		return 1
	fi

	local version major minor
	version="$(go version | awk '{print $3}' | sed 's/^go//')"
	major="${version%%.*}"
	minor="${version#*.}"
	minor="${minor%%.*}"

	[[ "${major}" -gt 1 || ( "${major}" -eq 1 && "${minor}" -ge 22 ) ]]
}

install_go() {
	if go_is_sufficient; then
		log "go already installed: $(go version)"
		return
	fi

	local arch tarball
	case "$(uname -m)" in
	x86_64) arch=amd64 ;;
	aarch64) arch=arm64 ;;
	*)
		log "unsupported architecture: $(uname -m)"
		exit 1
		;;
	esac

	tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
	log "installing Go ${GO_VERSION} for ${arch}"
	curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
	rm -rf /usr/local/go
	tar -C /usr/local -xzf "/tmp/${tarball}"
	rm -f "/tmp/${tarball}"

	cat >/etc/profile.d/alertyx-go.sh <<'EOF'
export PATH="/usr/local/go/bin:$PATH"
EOF
	chmod 0644 /etc/profile.d/alertyx-go.sh
	export PATH="/usr/local/go/bin:$PATH"

	if ! go_is_sufficient; then
		log "Go installation failed verification"
		exit 1
	fi
	log "installed $(go version)"
}

libbcc_present() {
	local candidate
	for candidate in \
		/usr/lib/x86_64-linux-gnu/libbcc.so \
		/usr/lib64/libbcc.so \
		/usr/lib/libbcc.so; do
		if [[ -f "${candidate}" ]]; then
			return 0
		fi
	done

	if ldconfig -p 2>/dev/null | grep -q 'libbcc\.so'; then
		return 0
	fi

	return 1
}

kernel_headers_present() {
	[[ -d "/usr/src/linux-headers-$(uname -r)" ]] && return 0
	[[ -d "/lib/modules/$(uname -r)/build" ]] && return 0
	return 1
}

verify_bcc_setup() {
	if ! libbcc_present; then
		log "libbcc not found after package install"
		exit 1
	fi

	if ! kernel_headers_present; then
		log "kernel headers not found for $(uname -r)"
		exit 1
	fi

	log "BCC runtime and kernel headers verified"
}

main() {
	require_os_release
	install_distro_packages
	install_go
	verify_bcc_setup
	log "provision complete"
}

main "$@"
