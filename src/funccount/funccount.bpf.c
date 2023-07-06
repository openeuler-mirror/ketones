// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Based on funccount.py - 2015 Brendan Gregg

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

#define MAX_ENTRIES	1024

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, __u64);
} counts SEC(".maps");

static __always_inline bool filter_pid(void)
{
	if (target_pid && target_pid != (bpf_get_current_pid_tgid() >> 32))
		return true;
	return false;
}

SEC("kprobe.multi")
int BPF_KPROBE(function_entry)
{
	if (filter_pid())
		return 0;

	static __u64 zero;
	__u64 ip = PT_REGS_IP(ctx);
	__u64 *count = bpf_map_lookup_or_try_init(&counts, &ip, &zero);

	if (!count)
		return 0;

	__sync_fetch_and_add(count, 1);
	return 0;
}

SEC("tracepoint")
int tracepoint_entry(void *ctx)
{
	if (filter_pid())
		return 0;

	static __u64 zero;
	__u64 *count = bpf_map_lookup_or_try_init(&counts, &zero, &zero);

	if (!count)
		return 0;

	__sync_fetch_and_add(count, 1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
