// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __SOFTIRQ_LATENCY_H
#define __SOFTIRQ_LATENCY_H

#define MAX_SLOTS	20

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif
