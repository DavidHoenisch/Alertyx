// SPDX-License-Identifier: GPL-2.0
// Listen event capture using BPF CO-RE.

#include "event_types.h"
#include "core_helpers.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("kprobe/inet_listen")
int kprobe_inet_listen(struct pt_regs *ctx)
{
	struct listen_event_t event = {};
	struct task_struct *task;
	struct socket *sock;
	struct sock *sk;
	struct inet_sock *inet;
	__be32 addr;
	__be16 port;

	gather_base((struct event_base_t *)&event);
	task = (struct task_struct *)bpf_get_current_task();
	submit_pwd(ctx, (struct event_base_t *)&event, sizeof(event), task, &events);

	sock = (struct socket *)PT_REGS_PARM1(ctx);
	sk = BPF_CORE_READ(sock, sk);
	inet = (struct inet_sock *)sk;
	addr = BPF_CORE_READ(inet, inet_rcv_saddr);
	port = BPF_CORE_READ(inet, inet_sport);

	event.backlog = (__u32)PT_REGS_PARM2(ctx);
	event.socktype = (__u16)BPF_CORE_READ(sock, type);
	event.addr = ((__u32)addr >> 8) | ((__u32)addr << 8);
	event.port = ((__u16)port >> 8) | ((__u16)port << 8);
	event.ret = EVENT_KIND_NORMAL;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

SEC("kretprobe/inet_listen")
int kretprobe_inet_listen(struct pt_regs *ctx)
{
	struct listen_event_t event = {};

	gather_base((struct event_base_t *)&event);
	event.retval = (__s32)PT_REGS_RC(ctx);
	event.ret = EVENT_KIND_RET;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}
