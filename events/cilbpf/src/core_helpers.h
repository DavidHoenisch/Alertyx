// SPDX-License-Identifier: GPL-2.0
// Shared CO-RE helpers for Alertyx cilium/ebpf programs.

#ifndef ALERTYX_CILBPF_CORE_HELPERS_H
#define ALERTYX_CILBPF_CORE_HELPERS_H

#include "core_types.h"
#include "bpf_core_read.h"
#include "event_types.h"

static __always_inline int gather_base(struct event_base_t *event)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent;
	__u64 uid_gid;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	uid_gid = bpf_get_current_uid_gid();
	event->uid = (__u32)uid_gid;

	parent = BPF_CORE_READ(task, real_parent);
	if (parent)
		event->ppid = BPF_CORE_READ(parent, tgid);
	return 0;
}

static __always_inline int submit_pwd(void *ctx, struct event_base_t *event,
				      __u32 event_size, struct task_struct *task,
				      void *events_map)
{
	struct dentry *walker = BPF_CORE_READ(task, fs, pwd.dentry);
	struct dentry *parent;

	if (!walker)
		return 0;

#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++) {
		if (bpf_core_field_exists(((struct dentry *)0)->d_name.name))
			BPF_CORE_READ_STR_INTO(event->pwd, walker, d_name.name);
		else if (bpf_core_field_exists(((struct dentry *)0)->d_shortname))
			bpf_core_read_str(event->pwd, sizeof(event->pwd),
					  &walker->d_shortname);

		event->ret = EVENT_KIND_PWD;
		bpf_perf_event_output(ctx, events_map, BPF_F_CURRENT_CPU, event,
				      event_size);

		parent = BPF_CORE_READ(walker, d_parent);
		if (!parent || parent == walker)
			break;
		walker = parent;
	}

	return 0;
}

#endif
