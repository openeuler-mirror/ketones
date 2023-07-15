// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __OPENSNOOP_H
#define __OPENSNOOP_H

#define TASK_COMM_LEN	16
#define NAME_MAX	255
#define INVALID_UID	((uid_t)-1)

struct args_t {
	const char *fname;
	int flags;
	unsigned short modes;
};

struct event {
	pid_t pid;
	pid_t ppid;
	uid_t uid;
	int ret;
	int flags;
	unsigned short modes;
	__u64 callers[2];
	char comm[TASK_COMM_LEN];
	char fname[NAME_MAX];
};

#endif
