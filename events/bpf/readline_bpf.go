package bpf

import (
	bpf "github.com/iovisor/gobpf/bcc"

	"github.com/DavidHoenisch/Alertyx/events"
)

func ReadlineBPF(evChan chan events.Event, ctx events.Ctx) {
	eventType := "readline"

	m := bpf.NewModule(`
		#include <uapi/linux/ptrace.h>
		`+reqFunctions+`

    struct event_t {
        `+eventBaseStr+`
        char str[80];
    };

    int get_return_value(struct pt_regs *ctx) {
        `+gatherStr+`
        `+getPwd+`
        bpf_probe_read(&event.str, sizeof(event.str), (void *)PT_REGS_RC(ctx));
       `+retStr+`
    }

`, []string{})
	defer m.Close()

	readlineUretprobe, err := m.LoadUprobe("get_return_value")
	if err != nil {
		ctx.Error <- "readline: failed to load get_return_value: " + err.Error()
		return
	}

	err = m.AttachUretprobe("/bin/bash", "readline", readlineUretprobe, -1)
	if err != nil {
		ctx.Error <- "readline: failed to attach return_value: " + err.Error()
		return
	}

	event := &events.Readline{}
	readEvents(event, evChan, ctx, m, eventType)
}
