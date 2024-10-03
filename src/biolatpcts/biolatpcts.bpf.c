// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on biolatpcts.py - Tejun Heo <tj@kernel.org>

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "biolatpcts.h"

#define min(a,b)	((a) < (b) ? (a) : (b))

const volatile __u32 major;
const volatile __u32 minor;
const volatile __u32 which;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, REDF_ARRAY_LEN);
	__type(key, u32);
	__type(value, u64);
} rwdf_100ms SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, REDF_ARRAY_LEN);
	__type(key, u32);
	__type(value, u64);
} rwdf_1ms SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, REDF_ARRAY_LEN);
	__type(key, u32);
	__type(value, u64);
} rwdf_10us SEC(".maps");

static int block_rq_complete(struct request *rq)
{
	unsigned int cmd_flags;
	u64 dur, time;
	size_t base, slot, position;
	u64 *value;

	switch (which) {
	case FROM_RQ_ALLOC:
		if (!BPF_CORE_READ(rq, alloc_time_ns))
			return 0;
		else
			time = BPF_CORE_READ(rq, alloc_time_ns);
		break;
	case AFTER_RQ_ALLOC:
		if (!BPF_CORE_READ(rq, start_time_ns))
			return 0;
		else
			time = BPF_CORE_READ(rq, start_time_ns);
		break;
	case ON_DEVICE:
		if (!BPF_CORE_READ(rq, io_start_time_ns))
			return 0;
		else
			time = BPF_CORE_READ(rq, io_start_time_ns);
		break;
	default:
		return 0;
	}

	if (!BPF_CORE_READ(rq, q, disk) ||
	    BPF_CORE_READ(rq, q, disk, major) != major ||
	    BPF_CORE_READ(rq, q, disk, first_minor) != minor)
		return 0;

	cmd_flags = BPF_CORE_READ(rq, cmd_flags);
	switch (cmd_flags & REQ_OP_MASK) {
	case REQ_OP_READ:
		base = 0;
		break;
	case REQ_OP_WRITE:
		base = 100;
		break;
	case REQ_OP_DISCARD:
		base = 200;
		break;
	case REQ_OP_FLUSH:
		base = 300;
		break;
	default:
		return 0;
	}

	dur = bpf_ktime_get_ns() - time;

	slot = min(dur / (100 * NSEC_PER_MSEC), 99);
	position = base + slot;
	value = bpf_map_lookup_elem(&rwdf_100ms, &position);
	if (value)
		__sync_fetch_and_add(value, 1);
	else
		return 0;

	if (slot)
		return 0;

	slot = min(dur / NSEC_PER_MSEC, 99);
	position = base + slot;
	value = bpf_map_lookup_elem(&rwdf_1ms, &position);
	if (value)
		__sync_fetch_and_add(value, 1);
	else
		return 0;

	if (slot)
		return 0;

	slot = min(dur / (10 * NSEC_PER_USEC), 99);
	position = base + slot;
	value = bpf_map_lookup_elem(&rwdf_10us, &position);
	if (value)
		__sync_fetch_and_add(value, 1);

	return 0;
}

SEC("raw_tp/block_rq_complete")
int BPF_PROG(block_rq_complete_raw, struct request *rq)
{
	return block_rq_complete(rq);
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete_btf, struct request *rq)
{
	return block_rq_complete(rq);
}

char LICENSE[] SEC("license") = "GPL";
