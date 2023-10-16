// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on dbstat.py - Sasha Goldshtein

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"
#include "bits.bpf.h"
#include "dbstat.h"

const volatile int threshold = 0;
const volatile bool microseconds = false;

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u64);
        __type(value, u64);
} entry SEC(".maps");

__u32 hists[MAX_SLOTS] = {};

SEC("usdt")
int BPF_USDT(trace_start)
{
	u64 timestamp = bpf_ktime_get_ns();
	u64 pid = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&entry, &pid, &timestamp, BPF_ANY);

	return 0;
}

SEC("usdt")
int BPF_USDT(trace_end)
{
	u64 *tsp;
	u64 slot;
	s64 delta;
	u64 ts = bpf_ktime_get_ns();
	u64 pid = bpf_get_current_pid_tgid();

	tsp = bpf_map_lookup_elem(&entry, &pid);
	if (!tsp)
		return 0;
	delta = (s64)(ts - *tsp);
	if (delta < 0)
		return 0;
	if (threshold > 0 && (delta / 1000000 < threshold))
		return 0;
	if (microseconds)
		slot = log2l(delta / 1000U);
	else
		slot = log2l(delta / 1000000U);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hists[slot], 1);
	bpf_map_delete_elem(&entry, &pid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
