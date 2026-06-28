package cilbpf

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/events/cilbpf/bpf"
)

func kernelOffset(name string) uint64 {
	data, err := os.ReadFile("src/offsets.h")
	if err != nil {
		return 0
	}
	prefix := "#define " + name + " "
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		var value uint64
		if _, err := fmt.Sscanf(strings.TrimSpace(line[len(prefix):]), "%d", &value); err != nil {
			return 0
		}
		return value
	}
	return 0
}

func TestLoadExecSpec(t *testing.T) {
	t.Helper()
	if err := LoadExecSpec(); err != nil {
		t.Fatalf("LoadExecSpec() error: %v", err)
	}
}

func TestExecEventLayoutMatchesUserspace(t *testing.T) {
	t.Helper()

	var goEvent events.Exec
	var bpfEvent bpf.ExecEvent

	if unsafe.Sizeof(goEvent) != unsafe.Sizeof(bpfEvent) {
		t.Fatalf("event size mismatch: events.Exec=%d bpf.ExecEvent=%d",
			unsafe.Sizeof(goEvent), unsafe.Sizeof(bpfEvent))
	}
}

func TestKernelOffsetsPresent(t *testing.T) {
	t.Helper()

	required := []string{
		"TASK_REAL_PARENT_OFF",
		"TASK_FS_OFF",
		"TASK_TGID_OFF",
		"FS_PWD_OFF",
		"PATH_DENTRY_OFF",
		"DENTRY_D_PARENT_OFF",
	}
	for _, name := range required {
		if kernelOffset(name) == 0 {
			t.Fatalf("expected non-zero %s", name)
		}
	}
}

func TestExecBPFProgramNames(t *testing.T) {
	t.Helper()

	spec, err := bpf.LoadExecCollectionSpec()
	if err != nil {
		t.Fatalf("LoadExecCollectionSpec() error: %v", err)
	}
	for _, name := range []string{"tp_enter_execve", "tp_exit_execve"} {
		if _, ok := spec.Programs[name]; !ok {
			t.Fatalf("missing program %q", name)
		}
	}
}
