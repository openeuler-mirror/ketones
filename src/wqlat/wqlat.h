// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2024 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
#ifndef __WQLAT_H
#define __WQLAT_H

#define WQ_NAME_LEN	24
#define MAX_SLOTS	30

struct wq_key {
	char wq_name[WQ_NAME_LEN];
};

struct wq_info {
	__u32 slots[MAX_SLOTS];
};

#endif
