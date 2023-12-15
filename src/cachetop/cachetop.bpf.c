// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Base on cachetop.py - COPYRIGHT: Copyright (c) 2016-present, Facebook, Inc.
#include "vmlinux.h"
#include "cachetop.h"
#include "maps.bpf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

const volatile pid_t target_pid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, u64);
} counts SEC(".maps");

static int __do_count(void *ctx, u64 nf)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 uid = bpf_get_current_uid_gid();
	u64 *valp = NULL;
	u64 zero = 0;

	if (target_pid != -1 && target_pid != pid)
		return 0;

	struct key_t key = {};
	key.nf = nf;
	key.pid = pid;
	key.uid = uid;
	bpf_get_current_comm(&(key.comm), sizeof(key.comm));

	valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (!valp)
		return 0;

	__sync_fetch_and_add(valp, 1);

	return 0;
}

SEC("kprobe/add_to_page_cache_lru")
int BPF_KPROBE(kprobe_add_to_page_cache_lru)
{
	return __do_count(ctx, NF_APCL);
}

SEC("kprobe/mark_page_accessed")
int BPF_KPROBE(kprobe_mark_page_accessed)
{
	return __do_count(ctx, NF_MPA);
}

SEC("kprobe/mark_buffer_dirty")
int BPF_KPROBE(kprobe_mark_buffer_dirty)
{
	return __do_count(ctx, NF_MBD);
}

SEC("kprobe/account_page_dirtied")
int BPF_KPROBE(kprobe_account_page_dirtied)
{
	return __do_count(ctx, NF_APD);
}

SEC("kprobe/folio_account_dirtied")
int BPF_KPROBE(kprobe_folio_account_dirtied)
{
	return __do_count(ctx, NF_APD);
}

SEC("tracepoint/writeback/writeback_dirty_folio")
int tracepoint_writeback_dirty_folio(struct trace_event_raw_sys_enter* ctx)
{
	return __do_count(ctx, NF_APD);
}

SEC("tracepoint/writeback/writeback_dirty_page")
int tracepoint_writeback_dirty_page(struct trace_event_raw_sys_enter* ctx)
{
	return __do_count(ctx, NF_APD);
}

char LICENSE[] SEC("license") = "GPL";
