// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __HARDIRQS_H
#define __HARDIRQS_H

#define MAX_SLOTS	20

typedef struct {
	char name[32];
} irq_key_t;

typedef struct {
	__u64 count;
	__u32 slots[MAX_SLOTS];
} info_t;

#endif
