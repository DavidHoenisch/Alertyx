package cilbpf

import (
	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/DavidHoenisch/Alertyx/events/cilbpf/bpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

const bashPath = "/bin/bash"

// ReadlineBPF loads cilium/ebpf bash readline uretprobe and streams decoded events.
func ReadlineBPF(evChan chan events.Event, ctx events.Ctx) {
	eventType := "readline"
	event := &events.Readline{}

	if err := rlimit.RemoveMemlock(); err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to adjust memlock rlimit", err)
		return
	}

	objs := bpf.ReadlineObjects{}
	if err := bpf.LoadReadlineObjects(&objs, nil); err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to load eBPF objects", err)
		return
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(bashPath)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to open "+bashPath, err)
		return
	}

	uretprobeLink, err := ex.Uretprobe("readline", objs.UretprobeBashReadline, nil)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to attach readline uretprobe", err)
		return
	}
	defer uretprobeLink.Close()

	rd, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to create perf reader", err)
		return
	}

	readEvents(event, evChan, ctx, rd, eventType)
	<-ctx.Quit
	rd.Close()
}
