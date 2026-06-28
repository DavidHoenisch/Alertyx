package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func integrationReadmePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "test", "integration", "README.md")
}

func readIntegrationReadme(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(integrationReadmePath(t))
	if err != nil {
		t.Fatalf("failed to read integration README: %v", err)
	}
	return string(data)
}

func TestIntegrationReadmeExists(t *testing.T) {
	if _, err := os.Stat(integrationReadmePath(t)); err != nil {
		t.Fatalf("test/integration/README.md not found: %v", err)
	}
}

func TestIntegrationReadmeDocumentsPrerequisites(t *testing.T) {
	content := readIntegrationReadme(t)
	required := []string{
		"## Prerequisites",
		"Vagrant",
		"VirtualBox",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("integration README must document prerequisite %q", marker)
		}
	}
}

func TestIntegrationReadmeDocumentsVMMatrix(t *testing.T) {
	content := readIntegrationReadme(t)
	required := []string{
		"## VM Test Matrix",
		"ubuntu-22",
		"ubuntu-24",
		"fedora-40",
		"arch",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("integration README must document VM %q", marker)
		}
	}
}

func TestIntegrationReadmeDocumentsQuickStartCommands(t *testing.T) {
	content := readIntegrationReadme(t)
	required := []string{
		"## Quick Start",
		"vagrant up ubuntu-22",
		"vagrant ssh ubuntu-22 -c \"cd /vagrant && sudo go test -tags=integration ./...\"",
		"-tags=integration",
		"sudo",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("integration README must document command %q", marker)
		}
	}
}

func TestIntegrationReadmeDocumentsHarnessAndExamples(t *testing.T) {
	content := readIntegrationReadme(t)
	required := []string{
		"## Test Framework",
		"harness.go",
		"NewHarness",
		"RunAndWait",
		"KernelRelease()",
		"TestIntegrationAllSourcesLoadOnKernel",
		"TestIntegrationL1005DetectsTmpWrite",
		"TestIntegrationL1002DetectsShadowAccess",
		"TestIntegrationT1098DetectsCrossUserAuthorizedKeysWrite",
		"## Troubleshooting",
		"provision.sh",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("integration README must document %q", marker)
		}
	}
}

func TestIntegrationReadmeDocumentsKernelMatrixRunner(t *testing.T) {
	content := readIntegrationReadme(t)
	required := []string{
		"## Kernel Matrix Runner",
		"scripts/test-kernel-matrix.sh",
		"libbpf",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("integration README must document %q", marker)
		}
	}
	if strings.Contains(content, "BCC") {
		t.Fatal("integration README must not reference BCC after cilium/ebpf migration")
	}
}
