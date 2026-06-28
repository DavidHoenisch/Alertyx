package bpf

import "github.com/cilium/ebpf"

// ExecEvent mirrors the kernel event_t layout emitted by exec.c.
type ExecEvent = execEventT

// ExecObjects holds loaded exec eBPF programs and maps.
type ExecObjects = execObjects

// LoadExecObjects loads compiled exec eBPF programs and maps into the kernel.
func LoadExecObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadExecObjects(obj, opts)
}

// LoadExecCollectionSpec returns the embedded exec collection spec.
func LoadExecCollectionSpec() (*ebpf.CollectionSpec, error) {
	return loadExec()
}
