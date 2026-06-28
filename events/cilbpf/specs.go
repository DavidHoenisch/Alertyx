package cilbpf

import (
	"fmt"

	"github.com/DavidHoenisch/Alertyx/events/cilbpf/bpf"
	"github.com/cilium/ebpf"
)

func validateCollectionSpec(spec *ebpf.CollectionSpec, programs []string) error {
	if spec == nil {
		return fmt.Errorf("nil collection spec")
	}
	for _, name := range programs {
		if _, ok := spec.Programs[name]; !ok {
			return fmt.Errorf("missing program %q in collection", name)
		}
	}
	if _, ok := spec.Maps["events"]; !ok {
		return fmt.Errorf("missing map %q in collection", "events")
	}
	return nil
}

// LoadExecSpec validates the embedded exec collection can be parsed.
func LoadExecSpec() error {
	spec, err := bpf.LoadExecCollectionSpec()
	if err != nil {
		return err
	}
	return validateCollectionSpec(spec, []string{"tp_enter_execve", "tp_exit_execve"})
}

// LoadOpenSpec validates the embedded open collection can be parsed.
func LoadOpenSpec() error {
	spec, err := bpf.LoadOpenCollectionSpec()
	if err != nil {
		return err
	}
	return validateCollectionSpec(spec, []string{"tp_enter_openat", "tp_exit_openat"})
}

// LoadListenSpec validates the embedded listen collection can be parsed.
func LoadListenSpec() error {
	spec, err := bpf.LoadListenCollectionSpec()
	if err != nil {
		return err
	}
	return validateCollectionSpec(spec, []string{"kprobe_inet_listen", "kretprobe_inet_listen"})
}

// LoadReadlineSpec validates the embedded readline collection can be parsed.
func LoadReadlineSpec() error {
	spec, err := bpf.LoadReadlineCollectionSpec()
	if err != nil {
		return err
	}
	return validateCollectionSpec(spec, []string{"uretprobe_bash_readline"})
}
