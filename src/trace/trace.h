// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Base on trace.py - Copyright (C) 2016 Sasha Goldshtein.

#ifndef __TRACE_H
#define __TRACE_H

#define MAX_ENTRIES	1024
#define TASK_COMM_LEN	16

enum TRACE_TYPE {
	KPROBE,
	UPROBE,
	TRACEPOINT,
	USDT,
};

struct key_t {
	__u32 uid;
	__u32 gid;
	__u32 pid;
	__u32 tid;
	__u64 retval;
	__u64 args[6];
	int cpu;
	int kernel_stack_id;
	int user_stack_id;
	char comm[TASK_COMM_LEN];
	struct task_struct *task;
};

struct value_t {
	__u64 count;
};

#endif // __TRACE_H
