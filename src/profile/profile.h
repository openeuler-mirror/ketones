// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __PROFILE_H
#define __PROFILE_H

#define TASK_COMM_LEN	16
#define MAX_CPU_NR	256

typedef struct {
	__u32 pid;
	__u32 tgid;
	int user_stack_id;
	int kernel_stack_id;
	char comm[TASK_COMM_LEN];
} profile_key_t;

#endif
