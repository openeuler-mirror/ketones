// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on stacksnoop.py - Brendan Gregg

#ifndef __STACKSNOOP_H
#define __STACKSNOOP_H

#define TASK_COMM_LEN	16

struct event {
	__u64 stack_id;
	pid_t pid;
	char comm[TASK_COMM_LEN];
	int cpu;
};

#endif
