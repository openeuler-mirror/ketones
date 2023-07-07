// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __NAPTIME_H
#define __NAPTIME_H

#define TASK_COMM_LEN	16

struct event {
	pid_t			ppid;
	pid_t			pid;
	char			pcomm[TASK_COMM_LEN];
	char			comm[TASK_COMM_LEN];
	__kernel_time64_t	tv_sec;
	long long		tv_nsec;
};

#endif
