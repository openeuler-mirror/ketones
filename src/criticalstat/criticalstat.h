// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __TCPRST_H
#define __TCPRST_H

#define PERF_MAX_STACK_DEPTH	127
#define MAX_ENTRIES		1024
#define TASK_COMM_LEN		16

struct data_t {
	__u64 time;
	__u64 stack_id;
	__u32 cpu;
	__u64 id;
	__u32 addrs[4];	/* indexed by addr_offs */
	char comm[TASK_COMM_LEN];
};

#endif
