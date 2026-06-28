package cilbpf

import (
	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/events/cilbpf/bpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// ExecBPF loads cilium/ebpf exec tracepoint programs and streams decoded events.
func ExecBPF(evChan chan events.Event, ctx events.Ctx) {
	eventType := "exec"
	event := &events.Exec{}

	if err := rlimit.RemoveMemlock(); err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to adjust memlock rlimit", err)
		return
	}

	objs := bpf.ExecObjects{}
	if err := bpf.LoadExecObjects(&objs, nil); err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to load eBPF objects", err)
		return
	}
	defer objs.Close()

	enterLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TpEnterExecve, nil)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to attach sys_enter_execve tracepoint", err)
		return
	}
	defer enterLink.Close()

	exitLink, err := link.Tracepoint("syscalls", "sys_exit_execve", objs.TpExitExecve, nil)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to attach sys_exit_execve tracepoint", err)
		return
	}
	defer exitLink.Close()

	rd, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to create perf reader", err)
		return
	}

	readEvents(event, evChan, ctx, rd, eventType)
	<-ctx.Quit
	rd.Close()
}
