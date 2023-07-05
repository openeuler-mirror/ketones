// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __CAPABLE_H
#define __CAPABLE_H

#define TASK_COMM_LEN	16

struct cap_event {
	__u32	pid;
	__u32	cap;
	gid_t	tgid;
	pid_t	uid;
	int	audit;
	int	insetid;
	int	ret;
	char	task[TASK_COMM_LEN];
};

struct key_t {
	pid_t	pid;
	gid_t	tgid;
	int	kernel_stack_id;
	int	user_stack_id;
};

enum uniqueness {
	UNQ_OFF,
	UNQ_PID,
	UNQ_CGROUP,
};

struct myinfo {
        __u64 pid_tgid;
        __u64 dev;
        __u64 ino;
};

#endif
