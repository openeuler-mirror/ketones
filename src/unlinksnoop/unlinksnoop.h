// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>

#ifndef __UNLINKSNOOP_H
#define __UNLINKSNOOP_H

#define PATH_MAX	4096
#define TASK_COMM_LEN	16

struct event {
	pid_t pid;
	pid_t ppid;
	char comm[TASK_COMM_LEN];
	char filename[PATH_MAX];
};

#endif // __UNLINKSNOOP_H
