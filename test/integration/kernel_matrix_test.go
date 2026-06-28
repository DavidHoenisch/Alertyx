package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type kernelCoverage struct {
	vmName string
	major  int
}

func TestVagrantfileCoversKernelMajors567(t *testing.T) {
	t.Helper()

	content := readVagrantfile(t)
	coverage := []kernelCoverage{
		{vmName: "ubuntu-22", major: 5},
		{vmName: "ubuntu-24", major: 6},
		{vmName: "fedora-40", major: 6},
		{vmName: "arch", major: 7},
	}

	majors := map[int]bool{}
	for _, entry := range coverage {
		defineMarker := `config.vm.define "` + entry.vmName + `"`
		if !strings.Contains(content, defineMarker) {
			t.Fatalf("Vagrantfile must define VM %q for kernel %d.x coverage", entry.vmName, entry.major)
		}
		majors[entry.major] = true
	}

	for _, major := range []int{5, 6, 7} {
		if !majors[major] {
			t.Fatalf("integration VM matrix must cover kernel %d.x", major)
		}
	}
}

func TestIntegrationReadmeDocumentsKernel567Matrix(t *testing.T) {
	t.Helper()

	path := filepath.Join(repoRoot(t), "test", "integration", "README.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read integration README: %v", err)
	}
	content := string(data)

	required := []string{
		"5.15",
		"6.8",
		"7.x",
		"ubuntu-22",
		"ubuntu-24",
		"arch",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("integration README must document kernel matrix marker %q", marker)
		}
	}
}

func kernelMatrixScriptPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "scripts", "test-kernel-matrix.sh")
}

func readKernelMatrixScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(kernelMatrixScriptPath(t))
	if err != nil {
		t.Fatalf("read test-kernel-matrix.sh: %v", err)
	}
	return string(data)
}

func TestKernelMatrixScriptExists(t *testing.T) {
	info, err := os.Stat(kernelMatrixScriptPath(t))
	if err != nil {
		t.Fatalf("test-kernel-matrix.sh not found: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Fatal("test-kernel-matrix.sh must be executable")
	}
}

func TestKernelMatrixScriptUsesStrictMode(t *testing.T) {
	content := readKernelMatrixScript(t)
	if !strings.Contains(content, "set -euo pipefail") {
		t.Fatal("test-kernel-matrix.sh must use set -euo pipefail")
	}
}

func TestKernelMatrixScriptRunsAllVMs(t *testing.T) {
	content := readKernelMatrixScript(t)
	required := []string{
		"ubuntu-22",
		"ubuntu-24",
		"fedora-40",
		"arch",
		"-tags=integration",
		"vagrant up",
		"vagrant ssh",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("test-kernel-matrix.sh must reference %q", marker)
		}
	}
}

func TestKernelMatrixScriptSyntaxValid(t *testing.T) {
	cmd := exec.Command("bash", "-n", kernelMatrixScriptPath(t))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("test-kernel-matrix.sh failed bash -n: %v\n%s", err, out)
	}
}

func TestCilbpfSourcesIntegrationTestCoversAllSources(t *testing.T) {
	path := filepath.Join(repoRoot(t), "test", "integration", "cilbpf_sources_integration_test.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cilbpf_sources_integration_test.go: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "//go:build integration") {
		t.Fatal("cilbpf_sources_integration_test.go must use //go:build integration")
	}

	required := []string{
		"TestIntegrationAllSourcesLoadOnKernel",
		"cilbpf.AllSources()",
		"KernelRelease()",
	}
	for _, marker := range required {
		if !strings.Contains(content, marker) {
			t.Fatalf("cilbpf_sources_integration_test.go must contain %q", marker)
		}
	}
}
