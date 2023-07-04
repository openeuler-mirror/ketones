// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __BIOTOP_H
#define __BIOTOP_H

#define REQ_OP_BIT	8
#define REQ_OP_MASK	((1 << REQ_OP_BIT) - 1)

#define TASK_COMM_LEN	16

/* For saving the timestamp and __data_len of each request */
struct start_req_t {
	__u64	ts;
	__u64	data_len;
};

/* For saving process info by request */
struct who_t {
	pid_t	pid;
	char	name[TASK_COMM_LEN];
};

/* the key of the output summary */
struct info_t {
	pid_t	pid;
	int	rwflag;
	int	major;
	int	minor;
	char	name[TASK_COMM_LEN];
};

/* the value of the output summary */
struct val_t {
	__u64	bytes;
	__u64	us;
	__u32	io;
};

#endif
