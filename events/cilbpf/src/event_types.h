// SPDX-License-Identifier: GPL-2.0
// Shared constants and event layout for cilium/ebpf programs.

#ifndef ALERTYX_CILBPF_EVENT_TYPES_H
#define ALERTYX_CILBPF_EVENT_TYPES_H

#include "common.h"
#include "bpf_tracing.h"

#define MAX_ARGS 20
#define COMM_LEN 16
#define ARG_SIZE 128
#define PWD_SIZE 128

#define EVENT_KIND_NORMAL 0
#define EVENT_KIND_PWD 1
#define EVENT_KIND_RET 2
#define EVENT_KIND_OTHER 3

struct event_t {
	__u32 uid;
	__u32 pid;
	__u32 ppid;
	__s32 retval;
	__s32 ret;
	char pwd[PWD_SIZE];
	char comm[COMM_LEN];
	char argv[ARG_SIZE];
};
struct event_t *unused_event __attribute__((unused));

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	unsigned long args[6];
};

struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long int id;
	long int ret;
};

#include "offsets.h"

#endif
