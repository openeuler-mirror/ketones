// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __TCPRST_H
#define __TCPRST_H

#define PERF_MAX_STACK_DEPTH	127
#define MAX_ENTRIES		1024

struct data_t {
	__u32 saddr_v4;
	__u32 daddr_v4;
	__u32 pid;
	__u16 sport;
	__u16 dport;
	__u8 state;
	__u8 direct;
	__u64 stack_id;
};

#endif
