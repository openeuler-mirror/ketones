// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __TCPACCEPT_H
#define __TCPACCEPT_H

#define TASK_COMM_LEN	16

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
	__u16 lport;
	__u16 dport;
	__u64 ip;
	char task[TASK_COMM_LEN];
};

#endif
