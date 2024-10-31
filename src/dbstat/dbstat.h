// SPDX-License-Identifier: GPL-2.0
#ifndef __DBSTAT_H
#define __DBSTAT_H

#define MAX_SLOTS		20
#define MAX_ENTRIES		1024
#define MAX_PID_TRACE_NUM	100

enum db_type {
	DB_TYPE_NONE,
	DB_TYPE_MYSQL,
	DB_TYPE_POSTGRESQL,
};

#endif
