// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on ugc.py - Sasha Goldshtein

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"
#include "compat.bpf.h"
#include "ugc.h"

const volatile pid_t target_pid = -1;
const volatile int target_language = LA_NONE;
const volatile int minimum = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct entry_t);
} entry SEC(".maps");

static __always_inline int handle_gc_begin(struct pt_regs *ctx, __u8 index)
{
	struct entry_t data = {};
	__u64 pid;

	data.start_ns = bpf_ktime_get_ns();
	pid = bpf_get_current_pid_tgid();

	if (target_language == LA_PYTHON) {
		data.field1 = 0;
		bpf_usdt_arg(ctx, 0, &data.field1);
	}

	bpf_map_update_elem(&entry, &pid, &data, BPF_ANY);

	return 0;
}

static __always_inline int handle_gc_end(struct pt_regs *ctx, int index)
{
	__u64 elapsed, pid;
	struct entry_t *data;
	struct gc_event_t *event;

	pid = bpf_get_current_pid_tgid();
	data = bpf_map_lookup_and_delete_elem(&entry, &pid);
	if (!data)
		return 0;

	elapsed = bpf_ktime_get_ns() - data->start_ns;
	if (elapsed < minimum) {
		return 0;
	}

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->elapsed_ns = elapsed;
	event->probe_index = index;

	switch (target_language) {
	case LA_NODE:
		event->field1 = 0;
		bpf_usdt_arg(ctx, 0, &event->field1);
		break;
	case LA_PYTHON:
		event->field2 = 0;
		bpf_usdt_arg(ctx, 0, &event->field2);
		event->field1 = data->field1;
		break;
	default:
		break;
	}

	submit_buf(ctx, event, sizeof(*event));

	return 0;
}

SEC("usdt")
int BPF_USDT(trace_gc__begin_1)
{
	return handle_gc_begin(ctx, 1);
}

SEC("usdt")
int BPF_USDT(trace_gc__end_1)
{
	return handle_gc_end(ctx, 1);
}

SEC("usdt")
int BPF_USDT(trace_gc__begin_2)
{
	return handle_gc_begin(ctx, 2);
}

SEC("usdt")
int BPF_USDT(trace_gc__end_2)
{
	return handle_gc_end(ctx, 2);
}

char LICENSE[] SEC("license") = "GPL";
