// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __NUMASCHED_H
#define __NUMASCHED_H

#define TASK_COMM_LEN	16
#define INVALID_PID	((pid_t)-1)

struct event {
	pid_t	pid;
	pid_t	tid;
	__u32	numa_node_id;
	__u32	prev_numa_node_id;
	char	comm[TASK_COMM_LEN];
};

#endif
