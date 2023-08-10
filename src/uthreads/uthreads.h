// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on uthreads.py - Sasha Goldshtein

#ifndef __UTHREADS_H
#define __UTHREADS_H

struct thread_event_t {
	long runtime_id;
	long native_id;
	char type[8];
	char name[80];
};

enum LANGUAGE {
	LA_NONE,
	LA_JAVA,
	LA_C,
};
#endif // __UTHREADS_H
