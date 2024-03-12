// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2024 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on wqlat.py - ping gan

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"
#include "bits.bpf.h"
#include "wqlat.h"

#define MAX_ENTRIES	1024

const volatile bool target_ns = false;
const volatile bool show_per_workqueue = false;
const volatile bool target_workqueue = false;
char workqueue_name[WQ_NAME_LEN] = {};

struct value {
	__u64 time;
	char name[WQ_NAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct value);
} start_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct wq_key);
	__type(value, struct wq_info);
} dists SEC(".maps");

static inline bool match_workqueue_name(const char *name)
{
	for (int i = 0; i < WQ_NAME_LEN; i++) {
		__u8 c1 = name[i];
		__u8 c2 = workqueue_name[i];

		if (c1 != c2)
			return false;
		if (!c1)
			break;
	}

	return true;
}

SEC("raw_tp/workqueue_queue_work")
int BPF_PROG(tracepoint_workqueue_queue_work, int req_cpu, struct pool_workqueue *pwq)
{
	struct value zero = {}, *start;
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	start = bpf_map_lookup_or_try_init(&start_map, &pid_tgid, &zero);
	if (!start)
		return 0;

	start->time = bpf_ktime_get_ns();
	bpf_probe_read_kernel_str(start->name, WQ_NAME_LEN, BPF_CORE_READ(pwq, wq, name));
	return 0;
}

SEC("raw_tp/workqueue_execute_start")
int BPF_PROG(tracepoint_workqueu_execute_start)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 delta = 0;
	struct wq_key key = {};
	struct wq_info zero = {}, *info;

	struct value *start = bpf_map_lookup_and_delete_elem(&start_map, &pid_tgid);
	if (!start)
		return 0;

	delta = bpf_ktime_get_ns() - start->time;
	if (delta < 0)
		return 0;

	if (!target_ns)
		delta /= 1000U;

	__u64 slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	if (target_workqueue && !match_workqueue_name(start->name))
		return 0;

	if (show_per_workqueue || target_workqueue)
		__builtin_memcpy(&key.wq_name, start->name, WQ_NAME_LEN);
	else
		__builtin_memcpy(&key.wq_name, "INIT_WQ_NAME", WQ_NAME_LEN);

	info = bpf_map_lookup_or_try_init(&dists, &key, &zero);
	if (!info)
		return 0;

	info->slots[slot]++;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
