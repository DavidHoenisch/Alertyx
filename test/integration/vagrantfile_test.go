package integration

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	return filepath.Join(filepath.Dir(filename), "..", "..")
}

func vagrantfilePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "Vagrantfile")
}

func readVagrantfile(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(vagrantfilePath(t))
	if err != nil {
		t.Fatalf("failed to read Vagrantfile: %v", err)
	}
	return string(data)
}

func TestVagrantfileExists(t *testing.T) {
	if _, err := os.Stat(vagrantfilePath(t)); err != nil {
		t.Fatalf("Vagrantfile not found: %v", err)
	}
}

func TestVagrantfileUsesVagrant2(t *testing.T) {
	content := readVagrantfile(t)
	if !strings.Contains(content, `Vagrant.configure("2")`) {
		t.Fatal("Vagrantfile must use Vagrant.configure(\"2\")")
	}
}

func TestVagrantfileDefinesMultiDistroVMs(t *testing.T) {
	content := readVagrantfile(t)
	required := []struct {
		name string
		box  string
	}{
		{"ubuntu-22", "ubuntu/jammy64"},
		{"ubuntu-24", "ubuntu/noble64"},
		{"fedora-40", "generic/fedora40"},
		{"arch", "archlinux/archlinux"},
	}

	for _, vm := range required {
		defineMarker := `config.vm.define "` + vm.name + `"`
		if !strings.Contains(content, defineMarker) {
			t.Fatalf("Vagrantfile must define VM %q", vm.name)
		}
		boxMarker := `node.vm.box = "` + vm.box + `"`
		if !strings.Contains(content, boxMarker) {
			t.Fatalf("VM %q must use box %q", vm.name, vm.box)
		}
	}
}

func TestVagrantfileSyncsRepoToVagrant(t *testing.T) {
	content := readVagrantfile(t)
	if !strings.Contains(content, `config.vm.synced_folder ".", "/vagrant"`) {
		t.Fatal("Vagrantfile must sync project root to /vagrant for in-VM test runs")
	}
}

func TestVagrantfileReferencesProvisionScript(t *testing.T) {
	content := readVagrantfile(t)
	if !strings.Contains(content, "test/integration/provision.sh") {
		t.Fatal("Vagrantfile must provision VMs via test/integration/provision.sh")
	}
}

func TestVagrantfileSetsPrimaryUbuntu22(t *testing.T) {
	content := readVagrantfile(t)
	if !strings.Contains(content, `config.vm.define "ubuntu-22", primary: true`) {
		t.Fatal("ubuntu-22 should be the primary VM for default vagrant commands")
	}
}
