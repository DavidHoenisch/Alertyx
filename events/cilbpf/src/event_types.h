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
#define FILENAME_SIZE 80

#define EVENT_KIND_NORMAL 0
#define EVENT_KIND_PWD 1
#define EVENT_KIND_RET 2
#define EVENT_KIND_OTHER 3

struct event_base_t {
	__u32 uid;
	__u32 pid;
	__u32 ppid;
	__s32 retval;
	__s32 ret;
	char pwd[PWD_SIZE];
};
struct event_base_t *unused_event_base __attribute__((unused));

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

struct open_event_t {
	__u32 uid;
	__u32 pid;
	__u32 ppid;
	__s32 retval;
	__s32 ret;
	char pwd[PWD_SIZE];
	__s16 dfd;
	char filename[FILENAME_SIZE];
	__s32 flags;
};
struct open_event_t *unused_open_event __attribute__((unused));

struct listen_event_t {
	__u32 uid;
	__u32 pid;
	__u32 ppid;
	__s32 retval;
	__s32 ret;
	char pwd[PWD_SIZE];
	__u32 addr;
	__u16 port;
	__u16 socktype;
	__u32 backlog;
};
struct listen_event_t *unused_listen_event __attribute__((unused));

struct readline_event_t {
	__u32 uid;
	__u32 pid;
	__u32 ppid;
	__s32 retval;
	__s32 ret;
	char pwd[PWD_SIZE];
	char str[FILENAME_SIZE];
};
struct readline_event_t *unused_readline_event __attribute__((unused));

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

#endif
