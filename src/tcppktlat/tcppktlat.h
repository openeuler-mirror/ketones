// SPDX-License-Identifier: GPL-2.0
#ifndef __TCPPKTLAT_H
#define __TCPPKTLAT_H

#define TASK_COMM_LEN	16

#define AF_INET		2
#define AF_INET6	10

struct event {
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	__u64 delta_us;
	pid_t pid;
	pid_t tid;
	__u16 dport;
	__u16 sport;
	__u16 family;
	char comm[TASK_COMM_LEN];
};

#endif
