// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __THREADSNOOP_H
#define __THREADSNOOP_H

#define TASK_COMM_LEN	16

struct event {
	pid_t pid;
	char comm[TASK_COMM_LEN];
	__u64 function_addr;
};

#endif
