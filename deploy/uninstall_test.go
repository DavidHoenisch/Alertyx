package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func uninstallScriptPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "deploy", "uninstall.sh")
}

func readUninstallScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(uninstallScriptPath(t))
	if err != nil {
		t.Fatalf("failed to read uninstall script: %v", err)
	}
	return string(data)
}

func TestUninstallScriptExists(t *testing.T) {
	info, err := os.Stat(uninstallScriptPath(t))
	if err != nil {
		t.Fatalf("uninstall script not found: %v", err)
	}
	if info.IsDir() {
		t.Fatal("uninstall script path is a directory")
	}
}

func TestUninstallScriptHasBashShebang(t *testing.T) {
	content := readUninstallScript(t)
	if !strings.HasPrefix(content, "#!/usr/bin/env bash\n") {
		t.Fatal("uninstall script must start with bash shebang")
	}
}

func TestUninstallScriptUsesStrictMode(t *testing.T) {
	content := readUninstallScript(t)
	if !strings.Contains(content, "set -euo pipefail") {
		t.Fatal("uninstall script must use set -euo pipefail")
	}
}

func TestUninstallScriptRequiresRoot(t *testing.T) {
	content := readUninstallScript(t)
	for _, fragment := range []string{"require_root", "EUID", "must run as root"} {
		if !strings.Contains(content, fragment) {
			t.Fatalf("uninstall script missing root check fragment %q", fragment)
		}
	}
}

func TestUninstallScriptStopsAndDisablesService(t *testing.T) {
	content := readUninstallScript(t)
	for _, fragment := range []string{
		"systemctl stop",
		"systemctl disable",
		"systemctl is-active",
		"systemctl is-enabled",
	} {
		if !strings.Contains(content, fragment) {
			t.Fatalf("uninstall script missing service teardown fragment %q", fragment)
		}
	}
}

func TestUninstallScriptRemovesServiceUnitAndBinary(t *testing.T) {
	content := readUninstallScript(t)
	required := []string{
		`${SERVICE_NAME}.service`,
		"/etc/systemd/system",
		`rm -f "${SERVICE_DEST}"`,
		`rm -f "${BINARY_PATH}"`,
		`INSTALL_PREFIX:-/usr/local`,
		`BINARY_NAME="alertyx"`,
	}
	for _, fragment := range required {
		if !strings.Contains(content, fragment) {
			t.Fatalf("uninstall script missing removal fragment %q", fragment)
		}
	}
}

func TestUninstallScriptReloadsSystemd(t *testing.T) {
	content := readUninstallScript(t)
	if !strings.Contains(content, "systemctl daemon-reload") {
		t.Fatal("uninstall script must reload systemd after removing unit file")
	}
}

func TestUninstallScriptSupportsConfigurablePaths(t *testing.T) {
	content := readUninstallScript(t)
	for _, envVar := range []string{"KEEP_BINARY", "INSTALL_PREFIX", "SYSTEMD_UNIT_DIR"} {
		if !strings.Contains(content, envVar) {
			t.Fatalf("uninstall script missing configurable env var %q", envVar)
		}
	}
}

func TestUninstallScriptMatchesInstallPaths(t *testing.T) {
	install := readInstallScript(t)
	uninstall := readUninstallScript(t)
	for _, fragment := range []string{
		`INSTALL_PREFIX:-/usr/local`,
		`SYSTEMD_UNIT_DIR:-/etc/systemd/system`,
		`SERVICE_NAME="alertyx"`,
		`BINARY_NAME="alertyx"`,
	} {
		if !strings.Contains(install, fragment) {
			t.Fatalf("install script missing shared path fragment %q", fragment)
		}
		if !strings.Contains(uninstall, fragment) {
			t.Fatalf("uninstall script missing shared path fragment %q", fragment)
		}
	}
}
