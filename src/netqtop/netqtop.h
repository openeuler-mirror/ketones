// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __NETQTOP_H
#define __NETQTOP_H

#define IFNAMSIZ	16
#define MAX_QUEUE_NUM	1024

/*
 * This union is use to store name of the specified interface
 * and read it as two different data types
 */
union name_buf {
	char name[IFNAMSIZ];
	struct {
		__u64 hi;
		__u64 lo;
	} name_int;
};

/* data retrieved in tracepoints */
struct queue_data {
	__u64 total_pkt_len;
	__u32 num_pkt;
	__u32 size_64B;
	__u32 size_512B;
	__u32 size_2K;
	__u32 size_16K;
	__u32 size_64K;
};

#endif
