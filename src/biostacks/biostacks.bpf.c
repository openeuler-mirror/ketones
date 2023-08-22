// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "biostacks.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"
#include "bits.bpf.h"

#define MAX_ENTRIES	10240

const volatile bool target_ms = false;
const volatile bool filter_dev = false;
const volatile __u32 target_dev = 0;

struct internal_rqinfo {
	u64 start_ts;
	struct rqinfo rqinfo;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct request *);
	__type(value, struct internal_rqinfo);
} rqinfos SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct rqinfo);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

static __always_inline int trace_start(void *ctx, struct request *rq, bool merge_bio)
{
	struct internal_rqinfo *i_rqinfop = NULL, i_rqinfo = {};
	struct gendisk *disk = get_disk(rq);
	u32 dev;

	dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
			   BPF_CORE_READ(disk, first_minor)) : 0;
	if (filter_dev && dev != target_dev)
		return 0;

	if (merge_bio)
		i_rqinfop = bpf_map_lookup_elem(&rqinfos, &rq);
	if (!i_rqinfop)
		i_rqinfop = &i_rqinfo;

	i_rqinfop->start_ts = bpf_ktime_get_ns();
	i_rqinfop->rqinfo.pid = bpf_get_current_pid_tgid();
	i_rqinfop->rqinfo.kern_stack_size =
		bpf_get_stack(ctx, i_rqinfop->rqinfo.kern_stack,
			      sizeof(i_rqinfop->rqinfo.kern_stack), 0);
	bpf_get_current_comm(&i_rqinfop->rqinfo.comm,
			     sizeof(i_rqinfop->rqinfo.comm));
	i_rqinfop->rqinfo.dev = dev;

	if (i_rqinfop == &i_rqinfo)
		bpf_map_update_elem(&rqinfos, &rq, i_rqinfop, BPF_ANY);

	return 0;
}

SEC("fentry/blk_account_io_start")
int BPF_PROG(blk_account_io_start, struct request *rq)
{
	return trace_start(ctx, rq, false);
}

SEC("kprobe/blk_account_io_start")
int BPF_KPROBE(kprobe_blk_account_io_start, struct request *rq)
{
	return trace_start(ctx, rq, false);
}

SEC("kprobe/blk_account_io_merge_bio")
int BPF_PROG(blk_account_io_merge_bio, struct request *rq)
{
	return trace_start(ctx, rq, true);
}

SEC("tp_btf/block_io_start")
int BPF_PROG(block_io_start, struct request *rq)
{
	return trace_start(ctx, rq, false);
}

static __always_inline int probe_blk_account_io_done(struct request *rq)
{
	u64 slot, ts = bpf_ktime_get_ns();
	struct internal_rqinfo *i_rqinfop;
	struct hist *histp;
	s64 delta;

	i_rqinfop = bpf_map_lookup_elem(&rqinfos, &rq);
	if (!i_rqinfop)
		return 0;

	delta = (s64)(ts - i_rqinfop->start_ts);
	if (delta < 0)
		goto cleanup;

	histp = bpf_map_lookup_or_try_init(&hists, &i_rqinfop->rqinfo, &zero);
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
	bpf_map_delete_elem(&rqinfos, &rq);

	return 0;
}

SEC("fentry/blk_account_io_done")
int BPF_PROG(blk_account_io_done, struct request *rq)
{
	return probe_blk_account_io_done(rq);
}

SEC("kprobe/blk_account_io_done")
int BPF_KPROBE(kprobe_blk_account_io_done, struct request *rq)
{
	return probe_blk_account_io_done(rq);
}

SEC("tp_btf/block_io_done")
int BPF_PROG(block_io_done, struct request *rq)
{
	return probe_blk_account_io_done(rq);
}

char LICENSE[] SEC("license") = "GPL";
