// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "biolatency.h"
#include "bits.bpf.h"
#include "core_fixes.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240

extern __u32 LINUX_KERNEL_VERSION __kconfig;

const volatile bool filter_memcg = false;
const volatile bool target_per_disk = false;
const volatile bool target_per_flag = false;
const volatile bool target_queued = false;
const volatile bool target_ms = false;
const volatile bool filter_dev = false;
const volatile __u32 target_dev = 0;
const volatile bool target_single = true;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct request *);
	__type(value, u64);
} start SEC(".maps");

static struct hist zero;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists SEC(".maps");

static int __always_inline trace_rq_start(struct request *rq, int issue)
{
	u64 ts;

	if (filter_memcg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	if (issue && target_queued && BPF_CORE_READ(rq, q, elevator))
		return 0;

	ts = bpf_ktime_get_ns();

	if (filter_dev) {
		struct gendisk *disk = get_disk(rq);
		u32 dev;

		dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
				BPF_CORE_READ(disk, first_minor)) : 0;
		if (target_dev != dev)
			return 0;
	}

	bpf_map_update_elem(&start, &rq, &ts, BPF_ANY);

	return 0;
}

static int handle_block_rq_insert(__u64 *ctx)
{
	/*
	 * commit a54895fs (v5.11-rc1) changed tracepoint argument list from
	 * TP_PROTO(struct request_queue *q, struct request *rq) to
	 * TP_PROTO(struct request *rq)
	 */
	if (!target_single)
		return trace_rq_start((void *)ctx[1], false);
	else
		return trace_rq_start((void *)ctx[0], false);
}

static int handle_block_rq_issue(__u64 *ctx)
{
	/*
	 * commit a54895fs (v5.11-rc1) changed tracepoint argument list from
	 * TP_PROTO(struct request_queue *q, struct request *rq) to
	 * TP_PROTO(struct request *rq)
	 */
	if (!target_single)
		return trace_rq_start((void *)ctx[1], true);
	else
		return trace_rq_start((void *)ctx[0], true);
}

static int handle_block_rq_complete(struct request *rq, int error,
				    unsigned int nr_bytes)
{
	u64 slot, *tsp, ts = bpf_ktime_get_ns();
	struct hist_key hkey = {};
	struct hist *histp;
	s64 delta;

	if (filter_memcg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	tsp = bpf_map_lookup_elem(&start, &rq);
	if (!tsp)
		return 0;

	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;

	if (target_per_disk) {
		struct gendisk *disk = get_disk(rq);

		hkey.dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
					BPF_CORE_READ(disk, first_minor)) : 0;
	}

	if (target_per_flag)
		hkey.cmd_flags = BPF_CORE_READ(rq, cmd_flags);

	histp = bpf_map_lookup_or_try_init(&hists, &hkey, &zero);
	if (!histp)
		goto cleanup;

	if (target_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&start, &rq);
	return 0;
}

SEC("tp_btf/block_rq_insert")
int BPF_PROG(block_rq_insert_btf)
{
	return handle_block_rq_insert(ctx);
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_rq_issue_btf)
{
	return handle_block_rq_issue(ctx);
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete_btf, struct request *rq, int error,
	     unsigned int nr_bytes)
{
	return handle_block_rq_complete(rq, error, nr_bytes);
}

SEC("raw_tp/block_rq_insert")
int BPF_PROG(block_rq_insert_raw)
{
	return handle_block_rq_insert(ctx);
}

SEC("raw_tp/block_rq_issue")
int BPF_PROG(block_rq_issue_raw)
{
	return handle_block_rq_issue(ctx);
}

SEC("raw_tp/block_rq_complete")
int BPF_PROG(block_rq_complete_raw, struct request *rq, int error,
	     unsigned int nr_bytes)
{
	return handle_block_rq_complete(rq, error, nr_bytes);
}

char LICENSE[] SEC("license") = "GPL";
