// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __CPUWALK_H
#define __CPUWALK_H

#define MAX_CPU_NR	256

struct hist {
	__u32 slots[MAX_CPU_NR];
};

#endif
