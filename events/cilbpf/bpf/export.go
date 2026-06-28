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

// OpenEvent mirrors the kernel open_event_t layout emitted by open.c.
type OpenEvent = openOpenEventT

// OpenObjects holds loaded open eBPF programs and maps.
type OpenObjects = openObjects

// LoadOpenObjects loads compiled open eBPF programs and maps into the kernel.
func LoadOpenObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadOpenObjects(obj, opts)
}

// LoadOpenCollectionSpec returns the embedded open collection spec.
func LoadOpenCollectionSpec() (*ebpf.CollectionSpec, error) {
	return loadOpen()
}

// ListenEvent mirrors the kernel listen_event_t layout emitted by listen.c.
type ListenEvent = listenListenEventT

// ListenObjects holds loaded listen eBPF programs and maps.
type ListenObjects = listenObjects

// LoadListenObjects loads compiled listen eBPF programs and maps into the kernel.
func LoadListenObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadListenObjects(obj, opts)
}

// LoadListenCollectionSpec returns the embedded listen collection spec.
func LoadListenCollectionSpec() (*ebpf.CollectionSpec, error) {
	return loadListen()
}

// ReadlineEvent mirrors the kernel readline_event_t layout emitted by readline.c.
type ReadlineEvent = readlineReadlineEventT

// ReadlineObjects holds loaded readline eBPF programs and maps.
type ReadlineObjects = readlineObjects

// LoadReadlineObjects loads compiled readline eBPF programs and maps into the kernel.
func LoadReadlineObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadReadlineObjects(obj, opts)
}

// LoadReadlineCollectionSpec returns the embedded readline collection spec.
func LoadReadlineCollectionSpec() (*ebpf.CollectionSpec, error) {
	return loadReadline()
}
