// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on biolatpcts.py - Tejun Heo <tj@kernel.org>

#ifndef __BIOLATPCTS_H
#define __BIOLATPCTS_H

#define REQ_OP_BITS	8

#define REQ_OP_MASK	((1 << REQ_OP_BITS) - 1)
#define NSEC_PER_USEC	1000L
#define NSEC_PER_MSEC	1000000L
#define REDF_ARRAY_LEN	400

enum start_stat {
	FROM_RQ_ALLOC,
	AFTER_RQ_ALLOC,
	ON_DEVICE,
};

#endif
