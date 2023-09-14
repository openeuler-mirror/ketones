// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __MYSQL_QSLOWER_H
#define __MYSQL_QSLOWER_H

#define QUERY_MAX	128
#define MAX_ENTRIES	10240

struct start_t {
	__u64 ts;
	char *query;
};

struct data_t {
	__u32 pid;
	__u64 delta;
	char query[QUERY_MAX];
};

#endif
