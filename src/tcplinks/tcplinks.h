// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>

#ifndef __TCPLINKS_H
#define __TCPLINKS_H

#define MAX_ENTRIES	1024

struct link {
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	__u64 prev_sent;
	__u64 sent;
	__u64 prev_received;
	__u64 received;
	pid_t pid;
	__u16 sport;
	__u16 dport;
	__u16 family;
	bool mark;
};

#endif
