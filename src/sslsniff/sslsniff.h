// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __SSL_SNIFF_H
#define __SSL_SNIFF_H

#define MAX_BUF_SIZE 8192
#define TASK_COMM_LEN 16

struct probe_SSL_data_t {
	__u64 timestamp_ns;
	__u64 delta_ns;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 len;
	int buf_filled;
	int rw;
	char comm[TASK_COMM_LEN];
	__u8 buf[MAX_BUF_SIZE];
	int is_handshake;
};

#ifndef min
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })
#endif

#endif
