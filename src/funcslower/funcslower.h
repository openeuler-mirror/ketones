// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Based on funcslower.py - Copyright 2017, Sasha Goldshtein

#ifndef __FUNCSLOWER_H
#define __FUNCSLOWER_H

#define TASK_COMM_LEN	16
#define MAX_ARGS	5

struct event {
	__u64 id;
	__u64 pid_tgid;
	__u64 duration_ns;
	__u64 retval;
	char comm[TASK_COMM_LEN];
	__u64 args[MAX_ARGS];
	int user_stack_id;
	int kernel_stack_id;
};

#endif
