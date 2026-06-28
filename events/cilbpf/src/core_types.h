// SPDX-License-Identifier: GPL-2.0
// Minimal kernel struct stubs for BPF CO-RE field relocations.

#ifndef ALERTYX_CILBPF_CORE_TYPES_H
#define ALERTYX_CILBPF_CORE_TYPES_H

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct qstr {
	const unsigned char *name;
};

struct dentry {
	struct qstr d_name;
	struct dentry *d_parent;
	char d_shortname[32];
};

struct path {
	struct dentry *dentry;
};

struct fs_struct {
	struct path pwd;
};

struct task_struct {
	struct task_struct *real_parent;
	__u32 tgid;
	struct fs_struct *fs;
};

struct inet_sock {
	__be32 inet_rcv_saddr;
	__be16 inet_sport;
};

struct sock {
};

struct socket {
	short type;
	struct sock *sk;
};

#pragma clang attribute pop

#endif
