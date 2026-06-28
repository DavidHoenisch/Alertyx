package cilbpf

import (
	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/events/cilbpf/bpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// ListenBPF loads cilium/ebpf inet_listen kprobe programs and streams decoded events.
func ListenBPF(evChan chan events.Event, ctx events.Ctx) {
	eventType := "listen"
	event := &events.Listen{}

	if err := rlimit.RemoveMemlock(); err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to adjust memlock rlimit", err)
		return
	}

	objs := bpf.ListenObjects{}
	if err := bpf.LoadListenObjects(&objs, nil); err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to load eBPF objects", err)
		return
	}
	defer objs.Close()

	kprobeLink, err := link.Kprobe("inet_listen", objs.KprobeInetListen, nil)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to attach inet_listen kprobe", err)
		return
	}
	defer kprobeLink.Close()

	kretprobeLink, err := link.Kretprobe("inet_listen", objs.KretprobeInetListen, nil)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to attach inet_listen kretprobe", err)
		return
	}
	defer kretprobeLink.Close()

	rd, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to create perf reader", err)
		return
	}

	events.ReadEvents(event, evChan, ctx, rd, eventType)
	<-ctx.Quit
	rd.Close()
}
