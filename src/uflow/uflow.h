// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Based on uflow.py - Sasha Goldshtein

#ifndef __UFLOW_H
#define __UFLOW_H

enum LANGUAGE {
	LA_NONE,
	LA_JAVA,
	LA_PERL,
	LA_PHP,
	LA_PYTHON,
	LA_RUBY,
	LA_TCL,
};

#define MAX_STRING_LEN	80
#define MAX_ENTRIES	1024

struct call_t {
	__u64 depth;
	__u64 pid;
	int cpu;
	char clazz[MAX_STRING_LEN];
	char method[MAX_STRING_LEN];
};

#endif // __UFLOW_H
