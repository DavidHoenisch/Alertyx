package cilbpf

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/events/cilbpf/bpf"
	"github.com/cilium/ebpf"
)

var bpf2goGeneratedFiles = []string{
	"exec_bpfel.go",
	"exec_bpfeb.go",
	"open_bpfel.go",
	"open_bpfeb.go",
	"listen_bpfel.go",
	"listen_bpfeb.go",
	"readline_bpfel.go",
	"readline_bpfeb.go",
}

func TestBPF2GOGeneratedFilesPresent(t *testing.T) {
	t.Helper()

	for _, name := range bpf2goGeneratedFiles {
		path := filepath.Join("bpf", name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing generated file %s: %v", path, err)
		}
	}
}

func TestLoadAllCollectionSpecs(t *testing.T) {
	t.Helper()

	for name, load := range map[string]func() error{
		"exec":     LoadExecSpec,
		"open":     LoadOpenSpec,
		"listen":   LoadListenSpec,
		"readline": LoadReadlineSpec,
	} {
		name, load := name, load
		t.Run(name, func(t *testing.T) {
			t.Helper()
			if err := load(); err != nil {
				t.Fatalf("Load%sSpec() error: %v", name, err)
			}
		})
	}
}

func TestEventLayoutsMatchUserspace(t *testing.T) {
	t.Helper()

	cases := []struct {
		name    string
		goEvent any
		bpfEvent any
	}{
		{"exec", events.Exec{}, bpf.ExecEvent{}},
		{"open", events.Open{}, bpf.OpenEvent{}},
		{"listen", events.Listen{}, bpf.ListenEvent{}},
		{"readline", events.Readline{}, bpf.ReadlineEvent{}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			if unsafe.Sizeof(tc.goEvent) != unsafe.Sizeof(tc.bpfEvent) {
				t.Fatalf("event size mismatch: events.%T=%d bpf event=%d",
					tc.goEvent, unsafe.Sizeof(tc.goEvent), unsafe.Sizeof(tc.bpfEvent))
			}
		})
	}
}

func TestAllBPFProgramNames(t *testing.T) {
	t.Helper()

	cases := []struct {
		name     string
		loadSpec func() (*ebpf.CollectionSpec, error)
		programs []string
	}{
		{
			name:     "exec",
			loadSpec: bpf.LoadExecCollectionSpec,
			programs: []string{"tp_enter_execve", "tp_exit_execve"},
		},
		{
			name:     "open",
			loadSpec: bpf.LoadOpenCollectionSpec,
			programs: []string{"tp_enter_openat", "tp_exit_openat"},
		},
		{
			name:     "listen",
			loadSpec: bpf.LoadListenCollectionSpec,
			programs: []string{"kprobe_inet_listen", "kretprobe_inet_listen"},
		},
		{
			name:     "readline",
			loadSpec: bpf.LoadReadlineCollectionSpec,
			programs: []string{"uretprobe_bash_readline"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			spec, err := tc.loadSpec()
			if err != nil {
				t.Fatalf("LoadCollectionSpec() error: %v", err)
			}
			for _, name := range tc.programs {
				if _, ok := spec.Programs[name]; !ok {
					t.Fatalf("missing program %q", name)
				}
			}
		})
	}
}
