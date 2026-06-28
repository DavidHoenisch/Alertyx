// SPDX-License-Identifier: GPL-2.0
// Exec event capture using BPF CO-RE.

#include "event_types.h"
#include "core_helpers.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

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

	gather_base((struct event_base_t *)&event);
	task = (struct task_struct *)bpf_get_current_task();
	submit_pwd(ctx, (struct event_base_t *)&event, sizeof(event), task, &events);

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

	gather_base((struct event_base_t *)&event);
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	event.retval = (__s32)ctx->ret;
	event.ret = EVENT_KIND_RET;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}
