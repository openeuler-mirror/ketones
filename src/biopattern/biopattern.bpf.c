// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "biopattern.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

const volatile bool filter_dev = false;
const volatile __u32 target_dev = 0;

extern __u32 LINUX_KERNEL_VERSION __kconfig;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, struct counter);
} counters SEC(".maps");

SEC("tracepoint/block/block_rq_complete")
int handle__block_rq_complete(void *args)
{
	struct counter *counterp, zero = {};
	sector_t sector;
	u32 nr_sector;
	u32 dev;

	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 18, 0)) {
		struct trace_event_raw_block_rq_completion___x *ctx = args;

		sector = BPF_CORE_READ(ctx, sector);
		nr_sector = BPF_CORE_READ(ctx, nr_sector);
		dev = BPF_CORE_READ(ctx, dev);
	} else {
		struct trace_event_raw_block_rq_complete___x *ctx = args;

		sector = BPF_CORE_READ(ctx, sector);
		nr_sector = BPF_CORE_READ(ctx, nr_sector);
		dev = BPF_CORE_READ(ctx, dev);
	}

	if (filter_dev && target_dev != dev)
		return 0;

	counterp = bpf_map_lookup_or_try_init(&counters, &dev, &zero);
	if (!counterp)
		return 0;
	if (counterp->last_sector) {
		if (counterp->last_sector == sector)
			__sync_fetch_and_add(&counterp->sequential, 1);
		else
			__sync_fetch_and_add(&counterp->random, 1);
		__sync_fetch_and_add(&counterp->bytes, nr_sector << 9);
	}
	counterp->last_sector = sector + nr_sector;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
