package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func provisionScriptPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "test", "integration", "provision.sh")
}

func readProvisionScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(provisionScriptPath(t))
	if err != nil {
		t.Fatalf("failed to read provision.sh: %v", err)
	}
	return string(data)
}

func TestProvisionScriptExists(t *testing.T) {
	info, err := os.Stat(provisionScriptPath(t))
	if err != nil {
		t.Fatalf("provision.sh not found: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Fatal("provision.sh must be executable")
	}
}

func TestProvisionScriptHasShebang(t *testing.T) {
	content := readProvisionScript(t)
	if !strings.HasPrefix(content, "#!/usr/bin/env bash") {
		t.Fatal("provision.sh must start with bash shebang")
	}
}

func TestProvisionScriptUsesStrictMode(t *testing.T) {
	content := readProvisionScript(t)
	if !strings.Contains(content, "set -euo pipefail") {
		t.Fatal("provision.sh must use set -euo pipefail")
	}
}

func TestProvisionScriptSupportsDistros(t *testing.T) {
	content := readProvisionScript(t)
	required := []string{
		"ubuntu",
		"debian",
		"fedora",
		"arch",
		"install_apt_packages",
		"install_dnf_packages",
		"install_pacman_packages",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("provision.sh must support %q", marker)
		}
	}
}

func TestProvisionScriptInstallsEbpfDependencies(t *testing.T) {
	content := readProvisionScript(t)
	required := []string{
		"libbpf-dev",
		"libbpf-devel",
		"linux-headers",
		"verify_ebpf_setup",
		"libbpf_present",
		"kernel_headers_present",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("provision.sh must install or verify eBPF dependency %q", marker)
		}
	}
	if strings.Contains(content, "libbcc") || strings.Contains(content, "bcc-devel") {
		t.Fatal("provision.sh must not install BCC packages after gobpf removal")
	}
}

func TestProvisionScriptInstallsGo(t *testing.T) {
	content := readProvisionScript(t)
	required := []string{
		"install_go",
		"go_is_sufficient",
		"go.dev/dl",
		"1.22",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("provision.sh must install Go (%q missing)", marker)
		}
	}
}

func TestProvisionScriptSyntaxValid(t *testing.T) {
	cmd := exec.Command("bash", "-n", provisionScriptPath(t))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("provision.sh failed bash -n: %v\n%s", err, out)
	}
}
