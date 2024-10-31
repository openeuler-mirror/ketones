// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on ucalls.py - Sasha Goldshtein

#ifndef __UGC_H
#define __UGC_H

enum LANGUAGE {
	LA_NONE,
	LA_NODE,
	LA_PYTHON,
	LA_RUBY,
};

struct entry_t {
        __u64 start_ns;
        long field1;
        long field2;
};

struct gc_event_t {
	__u64 probe_index;
	__u64 elapsed_ns;
	long field1;
	long field2;
	long field3;
	long field4;
	char string1[32];
	char string2[32];
};

#define MAX_STRING_LEN	80
#define MAX_ENTRIES	1024

#endif // __UGC_H
