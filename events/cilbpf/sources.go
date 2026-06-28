package cilbpf

import "github.com/DavidHoenisch/Alertyx/events"

// AllSources returns every cilium/ebpf event source for the monitor loop.
func AllSources() []func(chan events.Event, events.Ctx) {
	return []func(chan events.Event, events.Ctx){
		ExecBPF,
		ListenBPF,
		OpenBPF,
		ReadlineBPF,
	}
}
