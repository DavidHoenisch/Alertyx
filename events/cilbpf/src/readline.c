// SPDX-License-Identifier: GPL-2.0
// Readline event capture using BPF CO-RE.

#include "event_types.h"
#include "core_helpers.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("uretprobe/bash_readline")
int uretprobe_bash_readline(struct pt_regs *ctx)
{
	struct readline_event_t event = {};
	struct task_struct *task;

	gather_base((struct event_base_t *)&event);
	task = (struct task_struct *)bpf_get_current_task();
	submit_pwd(ctx, (struct event_base_t *)&event, sizeof(event), task, &events);

	bpf_probe_read_user(&event.str, sizeof(event.str), (void *)PT_REGS_RC(ctx));
	event.ret = EVENT_KIND_RET;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}
