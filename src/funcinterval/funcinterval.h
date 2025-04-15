// SPDX-License-Identifier: GPL-2.0
// Based on funcinterval.py - Edward Wu

#ifndef __FUNCINTERVAL_H
#define __FUNCINTERVAL_H

#define MAX_SLOTS	26

struct hist {
	__u32 slots[MAX_SLOTS];
};

#endif /* __FUNCINTERVAL_H */