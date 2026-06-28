package cilbpf

import (
	"testing"
	"unsafe"

	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/events/cilbpf/bpf"
)

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
