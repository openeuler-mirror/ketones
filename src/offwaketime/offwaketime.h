// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Base on offwaketime.py - Copyright 2016 Netflix, Inc.
#ifndef __OFFWAKETIME_H
#define __OFFWAKETIME_H

#define TASK_COMM_LEN	16
#define MAX_ENTRIES	10240
#define PF_KTHREAD	0x00200000 /* kernel thread */

/*
 *  w: waker   t: target
 *  k: kernel  u: user
 */
struct key_t {
	char waker[TASK_COMM_LEN];
	char target[TASK_COMM_LEN];
	__s64 w_k_stack_id;
	__s64 w_u_stack_id;
	__s64 t_k_stack_id;
	__s64 t_u_stack_id;
	__u64 t_pid;
	__u64 t_tgid;
	__u32 w_pid;
	__u32 w_tgid;
};

struct wokeby_t {
	char name[TASK_COMM_LEN];
	int k_stack_id;
	int u_stack_id;
	int w_pid;
	int w_tgid;
};

#endif
