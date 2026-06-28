package cilbpf

import (
	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/events/cilbpf/bpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// OpenBPF loads cilium/ebpf openat tracepoint programs and streams decoded events.
func OpenBPF(evChan chan events.Event, ctx events.Ctx) {
	eventType := "open"
	event := &events.Open{}

	if err := rlimit.RemoveMemlock(); err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to adjust memlock rlimit", err)
		return
	}

	objs := bpf.OpenObjects{}
	if err := bpf.LoadOpenObjects(&objs, nil); err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to load eBPF objects", err)
		return
	}
	defer objs.Close()

	enterLink, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TpEnterOpenat, nil)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to attach sys_enter_openat tracepoint", err)
		return
	}
	defer enterLink.Close()

	exitLink, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.TpExitOpenat, nil)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to attach sys_exit_openat tracepoint", err)
		return
	}
	defer exitLink.Close()

	rd, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to create perf reader", err)
		return
	}

	events.ReadEvents(event, evChan, ctx, rd, eventType)
	<-ctx.Quit
	rd.Close()
}
