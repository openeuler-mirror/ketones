// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on compactsnoop.py - Wenbo Zhang

#ifndef __COMPACTSNOOP_H
#define __COMPACTSNOOP_H

#define TASK_COMM_LEN		16
#define PERF_MAX_STACK_DEPTH	127

struct val_t {
	int nid;
	int idx;
	int order;
	int sync;
	int fragindex;
	int low;
	int min;
	int high;
	int free;
	__u64 ts;
};

struct data_t {
	__u32 pid;
	__u32 tid;
	int nid;
	int idx;
	int order;
	__u64 delta;
	__u64 ts;
	int sync;
	int fragindex;
	int low;
	int min;
	int high;
	int free;
	int status;
	int stack_id;
	char comm[TASK_COMM_LEN];
};

#endif
