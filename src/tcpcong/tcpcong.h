// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on tcpcong.py - Ping Gan

#ifndef __TCPCONG_H
#define __TCPCONG_H

#define MAX_SLOTS	26

typedef struct ip_flow_key {
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	__u16 lport;
	__u16 dport;
} ip_flow_key_t;

typedef struct data_val {
	__u64 open_dura;
	__u64 loss_dura;
	__u64 disorder_dura;
	__u64 recover_dura;
	__u64 cwr_dura;
	__u64 total_changes;
	__u64 last_ts;
	__u16 last_cong_stat;
} data_val_t;

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif
