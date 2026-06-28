package bpf

import (
	"strconv"

	"github.com/DavidHoenisch/Alertyx/events"
)

const (
	argSize      = 128
	commLen      = 16
	maxArgs      = 20
	fileNameSize = 80
)

var (
	eventBaseStr = `
	u32 uid;
	u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
	u32 ppid; // Parent PID as in the userspace term (i.e. task->real_parent->tgid in kernel)
	int retval;
	int ret;
	char pwd[128];
	`

	submitNormal = `
	event.ret = ` + strconv.Itoa(events.EventKindNormal) + `;
    events.perf_submit(ctx, &event, sizeof(struct event_t));
	return 0;
	`

	submitOther = `
	event.ret = ` + strconv.Itoa(events.EventKindOther) + `;
    events.perf_submit(ctx, &event, sizeof(struct event_t));
	return 0;
	`

	reqFunctions = `
	#include <linux/fs.h>
	#include <linux/fs_struct.h>
	#include <linux/dcache.h>
	BPF_PERF_OUTPUT(events);
	`

	getPwd = `
	struct dentry* walker = task->fs->pwd.dentry;

    for (int i = 0; i < ` + strconv.Itoa(maxArgs) + `; i++) {
		bpf_probe_read_str(&event.pwd, sizeof(event.pwd), walker->d_name.name);

		event.ret = ` + strconv.Itoa(events.EventKindPwd) + `;
	    events.perf_submit(ctx, &event, sizeof(struct event_t));

		walker = walker->d_parent;

		if (walker == walker->d_parent)
			break;
    }
	`

	gatherStr = `
	struct event_t event = {};
	struct task_struct *task;
	struct task_struct *parent = NULL;
	u64 uid_gid;

	task = (struct task_struct *)bpf_get_current_task();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	uid_gid = bpf_get_current_uid_gid();
	event.uid = uid_gid;
	bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
	bpf_probe_read(&event.ppid, sizeof(event.ppid), &parent->tgid);
	`

	retStr = `
	event.retval = PT_REGS_RC(ctx);
	event.ret = ` + strconv.Itoa(events.EventKindRet) + `;
	events.perf_submit(ctx, &event, sizeof(struct event_t));
	return 0;
	`
)
