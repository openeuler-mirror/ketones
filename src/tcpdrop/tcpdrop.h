// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __TCPDROP_H
#define __TCPDROP_H

#define PERF_MAX_STACK_DEPTH	127
#define MAX_ENTRIES		1024

struct data_t {
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	__u32 af;
	__u32 pid;
	__u16 sport;
	__u16 dport;
	__u8 state;
	__u8 tcpflags;
	__u64 stack_id;
};

#endif
