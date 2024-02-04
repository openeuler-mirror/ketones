// SPDX-License-Identifier: GPL-2.0
/*
 *   Jackie Liu <liuyun01@kylinos.cn>
 */
#ifndef __KVMEXIT_H
#define __KVMEXIT_H

#define REASON_NUM	76
#define MAX_TIDS	30

struct exit_count {
	__u64 exit_ct[REASON_NUM];
};

struct cache_info {
	__u64 cache_pid_tgid;
	struct exit_count cache_exit_ct;
};

#endif // __KVMEXIT_H
