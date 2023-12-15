// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __UOBJNEW_H
#define __UOBJNEW_H

#define MAX_EVENTS_ENTRY 2048

struct key_t {
	union {
		__u64 size;
		char name[50];
	} key;
};

struct val_t {
	__u64 total_size;
	__u64 num_allocs;
};

enum lang {
	LANG_NONE,
	LANG_C,
	LANG_JAVA,
	LANG_RUBY,
	LANG_TLC,
};

#endif