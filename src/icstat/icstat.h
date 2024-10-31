// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on icstat.bt - Brendan Gregg

#ifndef __ICSTAT_H
#define __ICSTAT_H

struct info {
	__u64 counts;
	__u64 missed;
};

#endif
