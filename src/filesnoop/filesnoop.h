// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>

#ifndef __FILESNOOP_H
#define __FILESNOOP_H

#define TASK_COMM_LEN	16
#define FSFILENAME_MAX	255

enum file_op {
	F_NONE,
	F_OPEN,
	F_OPENAT,
	F_OPENAT2,
	F_WRITE,
	F_WRITEV,
	F_READ,
	F_READV,
	F_RENAMEAT,
	F_RENAMEAT2,
	F_UNLINKAT,
	F_CLOSE,
	F_UTIMENSAT,
};

struct event {
	pid_t pid;
	pid_t ppid;
	char comm[TASK_COMM_LEN];
	enum file_op op;
	int ret;
	char filename[FSFILENAME_MAX];
	int fd;
};

#endif /* __FILESNOOP_H */
