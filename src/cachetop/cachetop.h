// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Base on cachetop.py - COPYRIGHT: Copyright (c) 2016-present, Facebook, Inc.
#ifndef __CACHETOP_H
#define __CACHETOP_H

#define TASK_COMM_LEN	16
#define MAX_ENTRIES	10240

enum {
	NF_APCL,
	NF_MPA,
	NF_MBD,
	NF_APD,
};

struct key_t {
	__u64 nf;
	pid_t pid;
	uid_t uid;
	char comm[TASK_COMM_LEN];
};

#endif
