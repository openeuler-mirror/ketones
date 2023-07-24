// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __WRITEBACK_H
#define __WRITEBACK_H

struct event {
	char name[32];
	int reason;
	long nr_pages;
	__u64 latency;
};

#endif
