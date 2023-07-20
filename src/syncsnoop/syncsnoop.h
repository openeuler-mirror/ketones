// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __SYNCSNOOP_H
#define __SYNCSNOOP_H

#define TASK_COMM_LEN		16
#define MAX_FUNC_NAME_LEN	256

struct event {
	pid_t pid;
	char comm[TASK_COMM_LEN];
	char funcname[MAX_FUNC_NAME_LEN];
};

#endif
