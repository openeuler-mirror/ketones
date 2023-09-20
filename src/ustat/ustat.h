// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on ustat.py - Sasha Goldshtein

#ifndef __USTAT_H
#define __USTAT_H

enum LANGUAGE {
	LA_NONE,
	LA_JAVA,
	LA_NODE,
	LA_PERL,
	LA_PHP,
	LA_PYTHON,
	LA_RUBY,
	LA_TCL,
};

enum CATEGORY {
	CA_NONE,
	CA_THREAD,
	CA_METHOD,
	CA_OBJNEW,
	CA_CLOAD,
	CA_EXCP,
	CA_GC,
};

#define MAX_ENTRIES	1024

#endif // __USTAT_H
