package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func deploymentReadmePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "deploy", "README.md")
}

func readDeploymentReadme(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(deploymentReadmePath(t))
	if err != nil {
		t.Fatalf("failed to read deployment README: %v", err)
	}
	return string(data)
}

func TestDeploymentReadmeExists(t *testing.T) {
	if _, err := os.Stat(deploymentReadmePath(t)); err != nil {
		t.Fatalf("deploy/README.md not found: %v", err)
	}
}

func TestDeploymentReadmeDocumentsPrerequisites(t *testing.T) {
	content := readDeploymentReadme(t)
	required := []string{
		"## Prerequisites",
		"eBPF",
		"Root privileges",
		"systemd",
		"go build",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("deployment README must document prerequisite %q", marker)
		}
	}
}

func TestDeploymentReadmeDocumentsQuickInstall(t *testing.T) {
	content := readDeploymentReadme(t)
	required := []string{
		"## Quick Install",
		"sudo ./deploy/install.sh",
		"/usr/local/bin/alertyx",
		"/etc/systemd/system/alertyx.service",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("deployment README must document quick install step %q", marker)
		}
	}
}

func TestDeploymentReadmeDocumentsInstallOptions(t *testing.T) {
	content := readDeploymentReadme(t)
	required := []string{
		"## Install Script Options",
		"INSTALL_PREFIX",
		"SYSTEMD_UNIT_DIR",
		"SKIP_BUILD",
		"NO_START",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("deployment README must document install option %q", marker)
		}
	}
}

func TestDeploymentReadmeDocumentsManualInstallation(t *testing.T) {
	content := readDeploymentReadme(t)
	required := []string{
		"## Manual Installation",
		"go build -o /usr/local/bin/alertyx",
		"install -m 0644 deploy/alertyx.service",
		"systemctl daemon-reload",
		"systemctl enable alertyx.service",
		"systemctl start alertyx.service",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("deployment README must document manual install step %q", marker)
		}
	}
}

func TestDeploymentReadmeDocumentsUninstall(t *testing.T) {
	content := readDeploymentReadme(t)
	required := []string{
		"## Uninstall",
		"sudo ./deploy/uninstall.sh",
		"KEEP_BINARY",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("deployment README must document uninstall step %q", marker)
		}
	}
}

func TestDeploymentReadmeDocumentsServiceManagement(t *testing.T) {
	content := readDeploymentReadme(t)
	required := []string{
		"## Service Management",
		"systemctl status alertyx.service",
		"systemctl restart alertyx.service",
		"journalctl -u alertyx.service",
		"monitor --syslog",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("deployment README must document service management step %q", marker)
		}
	}
}

func TestDeploymentReadmeDocumentsInstalledFiles(t *testing.T) {
	content := readDeploymentReadme(t)
	required := []string{
		"## Installed Files",
		"deploy/install.sh",
		"deploy/uninstall.sh",
		"deploy/alertyx.service",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("deployment README must document installed file %q", marker)
		}
	}
}

func TestDeploymentReadmeDocumentsTroubleshooting(t *testing.T) {
	content := readDeploymentReadme(t)
	required := []string{
		"## Troubleshooting",
		"Service fails to start",
		"journalctl -u alertyx.service",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("deployment README must document troubleshooting topic %q", marker)
		}
	}
}
