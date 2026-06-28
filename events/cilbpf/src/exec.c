// SPDX-License-Identifier: GPL-2.0
// Exec event capture for Alertyx cilium/ebpf proof-of-concept.

#include "event_types.h"

struct task_struct;

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline void *field_ptr(void *base, __u32 offset)
{
	return (void *)((char *)base + offset);
}

static __always_inline int gather_base(struct event_t *event)
{
	struct task_struct *task;
	void *parent = NULL;
	__u64 uid_gid;

	task = (struct task_struct *)bpf_get_current_task();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	uid_gid = bpf_get_current_uid_gid();
	event->uid = (__u32)uid_gid;

	bpf_probe_read_kernel(&parent, sizeof(parent),
			      field_ptr(task, TASK_REAL_PARENT_OFF));
	if (parent)
		bpf_probe_read_kernel(&event->ppid, sizeof(event->ppid),
				      field_ptr(parent, TASK_TGID_OFF));
	return 0;
}

static __always_inline int submit_pwd(void *ctx, struct event_t *event, struct task_struct *task)
{
	void *fs = NULL;
	void *pwd = NULL;
	void *walker = NULL;
	void *parent = NULL;

	bpf_probe_read_kernel(&fs, sizeof(fs), field_ptr(task, TASK_FS_OFF));
	if (!fs)
		return 0;

	bpf_probe_read_kernel(&pwd, sizeof(pwd), field_ptr(fs, FS_PWD_OFF));
	bpf_probe_read_kernel(&walker, sizeof(walker), field_ptr(pwd, PATH_DENTRY_OFF));
	if (!walker)
		return 0;

#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++) {
		if (DENTRY_D_NAME_OFF) {
			void *name = NULL;

			bpf_probe_read_kernel(&name, sizeof(name),
					      field_ptr(walker, DENTRY_D_NAME_OFF));
			if (name)
				bpf_probe_read_kernel_str(event->pwd, sizeof(event->pwd),
							  field_ptr(name, QSTR_NAME_OFF));
		} else if (DENTRY_SHORTNAME_OFF) {
			bpf_probe_read_kernel_str(event->pwd, sizeof(event->pwd),
						  field_ptr(walker, DENTRY_SHORTNAME_OFF));
		}

		event->ret = EVENT_KIND_PWD;
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

		bpf_probe_read_kernel(&parent, sizeof(parent),
				      field_ptr(walker, DENTRY_D_PARENT_OFF));
		if (!parent || parent == walker)
			break;
		walker = parent;
	}

	return 0;
}

static __always_inline int __submit_arg(void *ctx, void *ptr, struct event_t *event)
{
	bpf_probe_read_user(event->argv, sizeof(event->argv), ptr);
	event->ret = EVENT_KIND_OTHER;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
	return 1;
}

static __always_inline int submit_arg(void *ctx, void *ptr, struct event_t *event)
{
	const char *argp = NULL;

	bpf_probe_read_user(&argp, sizeof(argp), ptr);
	if (argp)
		return __submit_arg(ctx, (void *)(argp), event);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct event_t event = {};
	struct task_struct *task;
	unsigned long argv = ctx->args[1];
	unsigned long filename = ctx->args[0];

	gather_base(&event);
	task = (struct task_struct *)bpf_get_current_task();
	submit_pwd(ctx, &event, task);

	__submit_arg(ctx, (void *)filename, &event);

#pragma unroll
	for (int i = 1; i < MAX_ARGS; i++) {
		if (submit_arg(ctx, (void *)(argv + i * sizeof(void *)), &event) == 0)
			break;
	}

	event.ret = EVENT_KIND_NORMAL;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tp_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
	struct event_t event = {};

	gather_base(&event);
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	event.retval = (__s32)ctx->ret;
	event.ret = EVENT_KIND_RET;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}
