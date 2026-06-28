package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoModExcludesGobpf(t *testing.T) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(repoRoot(t), "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "iovisor/gobpf") {
		t.Fatal("go.mod must not reference github.com/iovisor/gobpf after BCC removal")
	}
}

func TestWorkflowUsesEbpfDepsScript(t *testing.T) {
	t.Helper()

	content := readWorkflow(t)
	if strings.Contains(content, "install-bcc-deps.sh") {
		t.Fatal("workflow must not reference install-bcc-deps.sh")
	}
	if !strings.Contains(content, "install-ebpf-deps.sh") {
		t.Fatal("workflow must install eBPF deps via install-ebpf-deps.sh")
	}
}

func TestLegacyBpfPackageRemoved(t *testing.T) {
	t.Helper()

	path := filepath.Join(repoRoot(t), "events", "bpf")
	if _, err := os.Stat(path); err == nil {
		t.Fatal("events/bpf legacy gobpf package must be removed")
	}
}
