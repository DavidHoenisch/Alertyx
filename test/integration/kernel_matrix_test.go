package integration

import (
	"os"
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
