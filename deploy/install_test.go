package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func installScriptPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "deploy", "install.sh")
}

func readInstallScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(installScriptPath(t))
	if err != nil {
		t.Fatalf("failed to read install script: %v", err)
	}
	return string(data)
}

func TestInstallScriptExists(t *testing.T) {
	info, err := os.Stat(installScriptPath(t))
	if err != nil {
		t.Fatalf("install script not found: %v", err)
	}
	if info.IsDir() {
		t.Fatal("install script path is a directory")
	}
}

func TestInstallScriptHasBashShebang(t *testing.T) {
	content := readInstallScript(t)
	if !strings.HasPrefix(content, "#!/usr/bin/env bash\n") {
		t.Fatal("install script must start with bash shebang")
	}
}

func TestInstallScriptUsesStrictMode(t *testing.T) {
	content := readInstallScript(t)
	if !strings.Contains(content, "set -euo pipefail") {
		t.Fatal("install script must use set -euo pipefail")
	}
}

func TestInstallScriptRequiresRoot(t *testing.T) {
	content := readInstallScript(t)
	for _, fragment := range []string{"require_root", "EUID", "must run as root"} {
		if !strings.Contains(content, fragment) {
			t.Fatalf("install script missing root check fragment %q", fragment)
		}
	}
}

func TestInstallScriptBuildsAndInstallsBinary(t *testing.T) {
	content := readInstallScript(t)
	required := []string{
		"go build",
		`install -m 0755`,
		`INSTALL_PREFIX:-/usr/local`,
		`BIN_DIR="${INSTALL_PREFIX}/bin"`,
		"alertyx",
	}
	for _, fragment := range required {
		if !strings.Contains(content, fragment) {
			t.Fatalf("install script missing binary install fragment %q", fragment)
		}
	}
}

func TestInstallScriptInstallsServiceFile(t *testing.T) {
	content := readInstallScript(t)
	required := []string{
		"alertyx.service",
		"/etc/systemd/system",
		`install -m 0644`,
	}
	for _, fragment := range required {
		if !strings.Contains(content, fragment) {
			t.Fatalf("install script missing service install fragment %q", fragment)
		}
	}
}

func TestInstallScriptConfiguresSystemd(t *testing.T) {
	content := readInstallScript(t)
	for _, fragment := range []string{
		"systemctl daemon-reload",
		"systemctl enable",
		"systemctl start",
	} {
		if !strings.Contains(content, fragment) {
			t.Fatalf("install script missing systemd fragment %q", fragment)
		}
	}
}

func TestInstallScriptSupportsSkipBuildAndNoStart(t *testing.T) {
	content := readInstallScript(t)
	for _, envVar := range []string{"SKIP_BUILD", "NO_START", "INSTALL_PREFIX", "SYSTEMD_UNIT_DIR"} {
		if !strings.Contains(content, envVar) {
			t.Fatalf("install script missing configurable env var %q", envVar)
		}
	}
}

func TestInstallScriptReferencesBundledServiceFile(t *testing.T) {
	content := readInstallScript(t)
	service := readService(t)
	if !strings.Contains(content, "alertyx.service") {
		t.Fatal("install script must reference alertyx.service")
	}
	if servicePath(t) != filepath.Join(repoRoot(t), "deploy", "alertyx.service") {
		t.Fatal("service file path mismatch")
	}
	if !strings.Contains(service, "ExecStart=/usr/local/bin/alertyx monitor --syslog") {
		t.Fatal("service file ExecStart must match install binary path")
	}
}
