// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#define ARGSIZE			128
#define TASK_COMM_LEN		16
#define TOTAL_MAX_ARGS		60
#define DEFAULT_MAX_ARGS	20
#define FULL_MAX_ARGS_ARR	(TOTAL_MAX_ARGS * ARGSIZE)
#define INVALID_UID		((uid_t)-1)
#define EVENT_SIZE(e)		((size_t)(&((struct event *)0)->args) + e->args_size)
#define LAST_ARG		(FULL_MAX_ARGS_ARR - ARGSIZE)

struct event {
	pid_t pid;
	pid_t ppid;
	uid_t uid;
	int retval;
	int args_count;
	unsigned int args_size;
	char comm[TASK_COMM_LEN];
	char args[FULL_MAX_ARGS_ARR];
};

#endif
