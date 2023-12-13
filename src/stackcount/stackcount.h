// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on stackcount.py - Brendan Gregg

#ifndef __STACKCOUNT_H
#define __STACKCOUNT_H

#define MAX_ENTRIES	1024
#define TASK_COMM_LEN	16

struct key_t {
	__u32 pid;
	int kernel_stack_id;
	int user_stack_id;
	char name[TASK_COMM_LEN];
};

struct value_t {
	__u64 count;
	int cpu;
};

#endif // __STACKCOUNT_H
