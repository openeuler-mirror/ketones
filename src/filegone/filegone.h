// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on filegone.py - Curu Wong

#ifndef __FILEGONE_H
#define __FILEGONE_H

#define DNAME_INLINE_LEN	32
#define TASK_COMM_LEN		16

struct event {
	pid_t pid;
	pid_t ppid;
	__u8 action;
	char comm[TASK_COMM_LEN];
	char fname[DNAME_INLINE_LEN];
	char fname2[DNAME_INLINE_LEN];
	int ret;
};

#endif // __FILEGONE_H
