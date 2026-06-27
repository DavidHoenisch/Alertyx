package bpf

import (
	bpf "github.com/iovisor/gobpf/bcc"

	"github.com/DavidHoenisch/Alertyx/events"
)

func ListenBPF(evChan chan events.Event, ctx events.Ctx) {
	eventType := "listen"
	m := bpf.NewModule(`
		#include <uapi/linux/ptrace.h>
		#include <net/inet_sock.h>
		`+reqFunctions+`

		struct event_t {
			`+eventBaseStr+`
			u32 addr;
			u16 port;
			u16 socktype;
			u32 backlog;
        };


        int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock, int backlog) {
            `+gatherStr+`
            `+getPwd+`

            struct sock *sk = sock->sk;
            struct inet_sock *inet = inet_sk(sk);

            u32 addr = 0;
            u16 port = 0;

            bpf_probe_read(&addr, sizeof(addr), &(inet->inet_rcv_saddr));
            bpf_probe_read(&port, sizeof(port), &(inet->inet_sport));

            event.backlog = backlog;
            event.socktype = sock->type;
            event.addr = (addr>>8) | (addr<<8);
            event.port = (port>>8) | (port<<8);
            `+submitNormal+`
        }

        int do_ret_inet_listen(struct pt_regs *ctx)
        {
            `+gatherStr+`
            `+retStr+`
        }
		`, []string{})
	defer m.Close()

	listenKprobe, err := m.LoadKprobe("kprobe__inet_listen")
	if err != nil {
		ctx.Error <- "listen: failed to load get_return_value: " + err.Error()
		return
	}

	err = m.AttachKprobe("inet_listen", listenKprobe, -1)
	if err != nil {
		ctx.Error <- "listen: failed to attach return_value: " + err.Error()
		return
	}

	kretprobe, err := m.LoadKprobe("do_ret_inet_listen")
	if err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to load do_ret_sys_openat", err)
		return
	}

	if err := m.AttachKretprobe("inet_listen", kretprobe, -1); err != nil {
		ctx.Error <- events.FormatError(eventType, "failed to attach do_ret_inet_listen", err)
		return
	}

	event := &events.Listen{}
	readEvents(event, evChan, ctx, m, eventType)
}
