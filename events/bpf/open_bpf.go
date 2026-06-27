package bpf

import (
	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/iovisor/gobpf/bcc"
)

func OpenBPF(evChan chan events.Event, ctx events.Ctx) {
	eventType := "open"
	event := &events.Open{}

	m := bcc.NewModule(`
		#include <uapi/linux/ptrace.h>
		#include <linux/sched.h>
		`+reqFunctions+`

		struct event_t {
			`+eventBaseStr+`
			s16 dfd;
			char filename[80];
			int flags;
		};

		int syscall__openat(struct pt_regs *ctx,
			int dfd,
			const char __user *filename,
			int flags,
			umode_t mode)
		{

			`+gatherStr+`
			`+getPwd+`

		    bpf_probe_read_str(&event.filename, sizeof(event.filename), filename);
			event.dfd = dfd;
			event.flags = flags;
			`+submitNormal+`
		}

		int do_ret_sys_openat(struct pt_regs *ctx) {
			`+gatherStr+`
			`+retStr+`
		}

	`, []string{})
	defer m.Close()

	fnName := bcc.GetSyscallFnName("openat")

	openKprobe, err := m.LoadKprobe("syscall__openat")
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to load get_return_value", err)
		return
	}

	err = m.AttachKprobe(fnName, openKprobe, -1)
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to attach return_value", err)
		return
	}

	kretprobe, err := m.LoadKprobe("do_ret_sys_openat")
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to load do_ret_sys_openat", err)
		return
	}

	if err := m.AttachKretprobe(fnName, kretprobe, -1); err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to attach do_ret_sys_openat", err)
		return
	}

	readEvents(event, evChan, ctx, m, eventType)
}
