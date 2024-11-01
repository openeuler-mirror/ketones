// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Shida Zhang <zhangshida@kylinos.cn>
//
// Base on cpuunclaimed.py - COPYRIGHT: Copyright (c) 2016, Netflix, Inc.
#ifndef __LLCSTAT_H
#define __LLCSTAT_H

struct event {
	char task[255];
	__u64 ts;
	__u64 cpu;
	__u64 len;
};

#endif
