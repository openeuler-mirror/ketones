// SPDX-License-Identifier: GPL-2.0
// Copyright @ 2023 - Kylin
// Author: Shida Zhang <zhangshida@kylinos.cn>
//
// Base on cpuunclaimed.py - COPYRIGHT: Copyright (c) 2016, Netflix, Inc.
#include "vmlinux.h"
#include "cpuunclaimed.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"
#include "compat.bpf.h"

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct event);
} values SEC(".maps");

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	struct event *e;
	unsigned int len;
	struct task_struct *task;
	int cpu = bpf_get_smp_processor_id();
	u64 now = bpf_ktime_get_ns();

	/*
	 * Fetch the run queue length from task->se.cfs_rq->nr_running. This is an
	 * unstable interface and may need maintenance. Perhaps a future version
	 * of BPF will support task_rq(p) or something similar as a more reliable
	 * interface.
	 */
	task = (struct task_struct *)bpf_get_current_task();
	len = BPF_CORE_READ(task, se.cfs_rq, nr_running);

	e = reserve_buf(sizeof(struct event));
	if (!e)
		return 0;

	e->cpu = cpu;
	e->ts = now;
	e->len = len;
	bpf_get_current_comm(&e->task, sizeof(e->task));

	submit_buf(ctx, e, sizeof(struct event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
