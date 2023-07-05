// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __DCSNOOP_H
#define __DCSNOOP_H

#define TASK_COMM_LEN	16
#define MAX_FILE_LEN	64

enum lookup_type {
	LOOKUP_MISS,
	LOOKUP_REFERENCE,
};

struct entry_t {
	char name[MAX_FILE_LEN];
};

struct event {
	pid_t pid;
	pid_t tid;
	enum lookup_type type;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILE_LEN];
};

#endif
