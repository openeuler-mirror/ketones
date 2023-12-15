// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __SETUIDS_H
#define __SETUIDS_H

#define TASK_COMM_LEN	16

enum UID_TYPE {
	SU_UID,
	SU_FSUID,
	SU_REUID,
};

struct event {
	pid_t pid;
	char comm[TASK_COMM_LEN];
	enum UID_TYPE type;
	uid_t uid;
	int ret;
	union {
		struct {
			uid_t ruid;
			uid_t euid;
			uid_t suid;
		};
		uid_t setuid;
	};
};

#endif
