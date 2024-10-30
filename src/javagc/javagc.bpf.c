// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>
#include <bpf/bpf_core_read.h>
#include "javagc.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100);
	__type(key, uint32_t);
	__type(value, struct data_t);
} data_map SEC(".maps");

__u64 time = 0;

static __always_inline int gc_start(void)
{
	struct data_t data = {};

	data.cpu = bpf_get_smp_processor_id();
	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&data_map, &data.pid, &data, BPF_ANY);

	return 0;
}

static __always_inline int gc_end(void *ctx)
{
	struct data_t *event;
	struct data_t *p;
	__u64 val, pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	p = bpf_map_lookup_and_delete_elem(&data_map, &pid);
	if (!p)
		return 0;

	val = bpf_ktime_get_ns() - p->ts;
	if (val < time)
		return 0;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->cpu = bpf_get_smp_processor_id();
	event->pid = pid;
	event->ts = val;
	submit_buf(ctx, event, sizeof(*event));

	return 0;
}

SEC("usdt")
int handle_gc_start(struct pt_regs *ctx)
{
	return gc_start();
}

SEC("usdt")
int handle_gc_end(struct pt_regs *ctx)
{
	return gc_end(ctx);
}

SEC("usdt")
int handle_mem_pool_gc_start(struct pt_regs *ctx)
{
	return gc_start();
}

SEC("usdt")
int handle_mem_pool_gc_end(struct pt_regs *ctx)
{
	return gc_end(ctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
