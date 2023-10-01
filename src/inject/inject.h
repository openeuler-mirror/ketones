// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __INJECT_H
#define __INJECT_H

#define STACK_MAX_DEPTH 9

enum inject_mode {
	KMALLOC_MODE,
	BIO_MODE,
	ALLOC_PAGE_MODE,
	MAX_MODE,
};

#endif
