package bpf

import (
	"fmt"
	"os"
	"strconv"

	"github.com/DavidHoenisch/Alertyx/events"
	"github.com/iovisor/gobpf/bcc"
)

import "C"

var execSource = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

` + reqFunctions + `

struct event_t {
	` + eventBaseStr + `
    char comm[` + strconv.Itoa(commLen) + `];
    char argv[` + strconv.Itoa(argSize) + `];
};

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct event_t *event)
{
    bpf_probe_read(event->argv, sizeof(event->argv), ptr);
    event->ret = ` + strconv.Itoa(events.EventKindOther) + `;
    events.perf_submit(ctx, event, sizeof(struct event_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct event_t *event)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), event);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
	` + gatherStr + `
    ` + getPwd + `

    __submit_arg(ctx, (void *)filename, &event);

    for (int i = 1; i < ` + strconv.Itoa(maxArgs) + `; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &event) == 0)
             break;
    }

    ` + submitNormal + `
}

int do_ret_sys_execve(struct pt_regs *ctx) {
	` + gatherStr + `
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
	` + retStr + `
}
`

func ExecBPF(evChan chan events.Event, ctx events.Ctx) {
	eventType := "exec"
	event := &events.Exec{}

	m := bcc.NewModule(execSource, []string{})
	defer m.Close()

	fnName := bcc.GetSyscallFnName("execve")

	kprobe, err := m.LoadKprobe("syscall__execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load syscall__execve: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKprobe(fnName, kprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach syscall__execve: %s\n", err)
		os.Exit(1)
	}

	kretprobe, err := m.LoadKprobe("do_ret_sys_execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load do_ret_sys_execve: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKretprobe(fnName, kretprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach do_ret_sys_execve: %s\n", err)
		os.Exit(1)
	}

	readEvents(event, evChan, ctx, m, eventType)
}
