// SPDX-License-Identifier: GPL-2.0
/*
 * Display the exit_reason and its statistics of each vm exit
 * for all vcpus of all virtual machines. For example:
 * $./kvmexit
 *  PID      TID      KVM_EXIT_REASON         COUNT
 *  1273551  1273568  MSR_WRITE               6
 *  1274253  1274261  EXTERNAL_INTERRUPT      1
 *  1274253  1274261  HLT                     12
 *  ...
 *
 * Besides, we also allow users to specify one pid, tid(s), or one
 * pid and its vcpu.
 *
 * @PID: each vitual machine's pid in the user space.
 * @TID: the user space's thread of each vcpu of that virtual machine.
 * @KVM_EXIT_REASON: the reason why the vm exits.
 * @COUNT: the counts of the @KVM_EXIT_REASONS.
 *
 * REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support)
 *
 * Copyright (c) 2021 ByteDance Inc. All rights reserved.
 * Copyright (c) 2024 Kylin Software Inc.
 *
 * Author(s):
 *   Fei Li <lifei.shirley@bytedance.com>
 *   Jackie Liu <liuyun01@kylinos.cn>
 */
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "kvmexit.h"
#include "maps.bpf.h"

#define TGID_NUM	1024

const volatile pid_t target_pid = 0;
const volatile pid_t target_tid = 0;

pid_t target_tids[MAX_TIDS] = {};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, TGID_NUM);
	__type(key, __u64);
	__type(value, struct exit_count);
} pcpu_kvm_stat SEC(".maps");

static struct exit_count init_value;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct cache_info);
} pcpu_cache SEC(".maps");

static __always_inline int __kvm_exit(unsigned int exit_reason)
{
	__u64 zero = 0;
	struct exit_count *tmp_info = NULL;
	struct cache_info *cache_p;
	int i;

	if (exit_reason >= REASON_NUM)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();

	if (target_pid && target_pid != pid_tgid >> 32)
		return 0;

	if (target_tid && target_tid != (pid_t)pid_tgid)
		return 0;

	if (target_tids[0]) {
		for (i = 0; i < MAX_TIDS && target_tids[i]; i++) {
			if (target_tids[i] == (pid_t)pid_tgid)
				goto found;
		}
		return 0;
	}

found:
	cache_p = bpf_map_lookup_elem(&pcpu_cache, &zero);
	if (!cache_p)
		return 0;

	if (cache_p->cache_pid_tgid == pid_tgid) {
		/* If the current pid_tgid hit his physical cpu consecutively,
		 * save it to pcpu_cache
		 */
		tmp_info = &cache_p->cache_exit_ct;
		tmp_info->exit_ct[exit_reason]++;
	} else {
		/* Try to load the last cache struct if exists. */
		tmp_info = bpf_map_lookup_or_try_init(&pcpu_kvm_stat, &pid_tgid, &init_value);
		if (!tmp_info)
			return 0;

		tmp_info->exit_ct[exit_reason]++;

		if (cache_p->cache_pid_tgid != 0) {
			/* Let's save the last hit cache_info into kvm_stat. */
			bpf_map_update_elem(&pcpu_kvm_stat, &cache_p->cache_pid_tgid,
					    &cache_p->cache_exit_ct, BPF_ANY);
		}
		cache_p->cache_pid_tgid = pid_tgid;
		bpf_core_read(&cache_p->cache_exit_ct, sizeof(*tmp_info), tmp_info);
	}

	return 0;
}

SEC("tp_btf/kvm_exit")
int BPF_PROG(tracepoint_kvm_exit_btf, unsigned int exit_reason)
{
	return __kvm_exit(exit_reason);
}

SEC("raw_tp/kvm_exit")
int BPF_PROG(tracepoint_kvm_exit_raw, unsigned int exit_reason)
{
	return __kvm_exit(exit_reason);
}

char LICENSE[] SEC("license") = "GPL";
