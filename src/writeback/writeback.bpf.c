// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Author: Copyright @ 2023 - Jackie Liu
//
// Based on bpftrace/writeback.bt - Brendan Gregg
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "compat.bpf.h"
#include "maps.bpf.h"
#include "writeback.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, dev_t);
	__type(value, __u64);
} birth SEC(".maps");

SEC("tracepoint/writeback/writeback_start")
int tracepoint_writeback_start(struct trace_event_raw_writeback_work_class *ctx)
{
	dev_t sb_dev = ctx->sb_dev;
	__u64 start = bpf_ktime_get_ns();

	bpf_map_update_elem(&birth, &sb_dev, &start, BPF_ANY);
	return 0;
}

SEC("tracepoint/writeback/writeback_written")
int tracepoint_writeback_written(struct trace_event_raw_writeback_work_class *ctx)
{
	struct event *event;

	long nr_pages = ctx->nr_pages;
	dev_t sb_dev = ctx->sb_dev;
	int reason = ctx->reason;
	__s64 latency;

	__u64 *start = bpf_map_lookup_and_delete_elem(&birth, &sb_dev);
	if (!start)
		return 0;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	BPF_CORE_READ_STR_INTO(&event->name, ctx, name);
	event->nr_pages = nr_pages;
	event->reason = reason;

	latency = bpf_ktime_get_ns() - *start;
	if (latency < 0)
		latency = 0;

	event->latency = latency / 1000;
	submit_buf(ctx, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
