// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __SOFDSNOOP_H
#define __SOFDSNOOP_H

#define MAX_FD 10
#define TASK_COMM_LEN 16

enum action_opt {
	ACTION_SEND,
	ACTION_RECV,
};

struct val_t {
	__u64 id;
	__u64 ts;
	enum action_opt action;
	int sock_fd;
	int fd_cnt;
	int fd[MAX_FD];
	char comm[TASK_COMM_LEN];
};

#endif
