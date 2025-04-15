// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on dirtop.py - Erwan Velu

#ifndef __DIRTOP_H
#define __DIRTOP_H

#define MAX_DIR_NUM	15
#define PATH_NAME_LEN	1024

enum op {
	READ,
	WRITE,
};

// the key for the output summary
struct key_t {
	unsigned long inode_id;
};

// the value of the output summary
struct val_t {
	__u64 reads;
	__u64 writes;
	__u64 rbytes;
	__u64 wbytes;
};

#endif
