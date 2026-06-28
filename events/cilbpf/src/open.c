// SPDX-License-Identifier: GPL-2.0
// Open event capture using BPF CO-RE.

#include "event_types.h"
#include "core_helpers.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct open_event_t event = {};
	struct task_struct *task;

	gather_base((struct event_base_t *)&event);
	task = (struct task_struct *)bpf_get_current_task();
	submit_pwd(ctx, (struct event_base_t *)&event, sizeof(event), task, &events);

	event.dfd = (__s16)ctx->args[0];
	bpf_probe_read_user_str(event.filename, sizeof(event.filename),
				(const char *)ctx->args[1]);
	event.flags = (__s32)ctx->args[2];
	event.ret = EVENT_KIND_NORMAL;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tp_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
	struct open_event_t event = {};

	gather_base((struct event_base_t *)&event);
	event.retval = (__s32)ctx->ret;
	event.ret = EVENT_KIND_RET;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}
