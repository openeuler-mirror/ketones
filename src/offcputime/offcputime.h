// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __OFFCPUTIME_H
#define __OFFCPUTIME_H

#define TASK_COMM_LEN	16

typedef struct {
	__u32 pid;
	__u32 tgid;
	int user_stack_id;
	int kernel_stack_id;
} offcpu_key_t;

typedef struct {
	__u64 delta;
	char comm[TASK_COMM_LEN];
} offcpu_val_t;

#endif
