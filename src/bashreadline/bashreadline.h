// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __BASHREADLINE_H
#define __BASHREADLINE_H

#define MAX_LINE_SIZE	80

typedef struct {
	__u32 pid;
	char str[MAX_LINE_SIZE];
} readline_str_t;

#endif
