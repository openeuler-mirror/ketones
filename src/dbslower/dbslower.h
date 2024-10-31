// SPDX-License-Identifier: GPL-2.0
#ifndef __DBSLOWER_H
#define __DBSLOWER_H

#define MAX_ENTRIES           10240
#define BINARY_PATH_BUF_SIZE  256
#define MAX_PID_TRACE_NUM     100

enum db_type {
	DB_TYPE_NONE,
	DB_TYPE_MYSQL,
	DB_TYPE_POSTGRESQL,
};

enum db_mode {
	DB_MODE_NONE,
	DB_MODE_USDT,
	DB_MODE_MYSQL56,
	DB_MODE_MYSQL57,
};

struct data_t {
	__u32 pid;
	__u64 duration;
	char query[256];
};

#endif
