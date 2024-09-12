// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __SYNCSNOOP_H
#define __SYNCSNOOP_H

#define TASK_COMM_LEN		16

enum sync_syscalls {
	SYS_T_MIN,
	SYS_SYNC,
	SYS_FSYNC,
	SYS_FDATASYNC,
	SYS_MSYNC,
	SYS_SYNC_FILE_RANGE,
	SYS_SYNCFS,
	SYS_T_MAX,
};

struct event {
	pid_t pid;
	__u64 ts_us;
	char comm[TASK_COMM_LEN];
	int sys;
};

#endif
