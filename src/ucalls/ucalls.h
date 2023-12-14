// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Based on ucalls.py - Sasha Goldshtein

#ifndef __UCALLS_H
#define __UCALLS_H

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

struct method_t {
	char clazz[MAX_STRING_LEN];
	char method[MAX_STRING_LEN];
};

struct info_t {
	__u64 num_calls;
	__u64 total_ns;
};

#endif // __UCALLS_H
