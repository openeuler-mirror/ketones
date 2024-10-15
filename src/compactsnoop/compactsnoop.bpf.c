// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on compactsnoop.py - Wenbo Zhang

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "compactsnoop.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

extern bool CONFIG_NUMA __kconfig;
const volatile bool extended_fields = true;
const volatile __u32 target_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, struct val_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 2048);
	__type(key, u32);
	__type(value, unsigned long[PERF_MAX_STACK_DEPTH]);
} stack_traces SEC(".maps");


// #define zone_idx(zone) ((zone) - (zone)->zone_pgdat->node_zones)
static inline int zone_idx_(struct zone *zone)
{
	struct pglist_data *zone_pgdat = BPF_CORE_READ(zone, zone_pgdat);

	return ((u64)zone - (u64)(zone_pgdat->node_zones)) / sizeof(struct zone);
}

static inline void get_all_wmark_pages(struct zone *zone, struct val_t *valp)
{
	u64 _watermark[NR_WMARK] = {};
	u64 watermark_boost = 0;

	BPF_CORE_READ_INTO(&_watermark, zone, _watermark);
	BPF_CORE_READ_INTO(&watermark_boost, zone, watermark_boost);
	valp->min = _watermark[WMARK_MIN] + watermark_boost;
	valp->low = _watermark[WMARK_LOW] + watermark_boost;
	valp->high = _watermark[WMARK_HIGH] + watermark_boost;
	BPF_CORE_READ_INTO(&valp->free, zone, vm_stat[NR_FREE_PAGES]);
}

static inline void submit_event(void *ctx, int status)
{
	struct data_t *data;
	u64 ts = bpf_ktime_get_ns();
	u64 id = bpf_get_current_pid_tgid();
	struct val_t *valp = bpf_map_lookup_and_delete_elem(&start, &id);

	if (valp == NULL)
		return;

	data = reserve_buf(sizeof(*data));
	if (!data)
		return;

	data->delta = ts - valp->ts;
	data->ts = ts / 1000;
	data->pid = id >> 32;
	data->tid = id;
	bpf_get_current_comm(&data->comm, sizeof(data->comm));
	data->nid = valp->nid;
	data->idx = valp->idx;
	data->order = valp->order;
	data->sync = valp->sync;

	if (extended_fields) {
		data->fragindex = valp->fragindex;
		data->min = valp->min;
		data->low = valp->low;
		data->high = valp->high;
		data->free = valp->free;
	}

	data->status = status;
	data->stack_id = bpf_get_stackid(ctx, &stack_traces, 0);

	submit_buf(ctx, data, sizeof(*data));
}

static inline void fill_compact_info(struct val_t *valp,
                                     struct zone *zone,
                                     int order)
{
	if (CONFIG_NUMA)
		BPF_CORE_READ_INTO(&valp->nid, zone, node);
	else
		valp->nid = 0;
	valp->idx = zone_idx_(zone);
	valp->order = order;
}

static int mm_compaction_suitable(struct zone *zone, int order, int ret)
{
	struct val_t val = { };
	struct val_t *valp;
	u64 id;

	if(ret != COMPACT_CONTINUE)
		return 0;

	id = bpf_get_current_pid_tgid();
	if (target_tgid && target_tgid != (id >> 32))
		return 0;

	if (extended_fields) {
		valp = bpf_map_lookup_elem(&start, &id);
		if (valp == NULL) {
			val.fragindex = -1000;
			valp = &val;
		}
		fill_compact_info(valp, zone, order);
		get_all_wmark_pages(zone, valp);
		bpf_map_update_elem(&start, &id, valp, BPF_ANY);
	} else {
		fill_compact_info(&val, zone, order);
		bpf_map_update_elem(&start, &id, &val, BPF_ANY);
	}

	return 0;
}

SEC("raw_tp/mm_compaction_suitable")
int BPF_PROG(mm_compaction_suitable_raw, struct zone *zone, int order, int ret)
{
	return mm_compaction_suitable(zone, order, ret);
}

SEC("tracepoint/compaction/mm_compaction_begin")
int trace_mm_compaction_begin(struct trace_event_raw_mm_compaction_begin *ctx)
{
	bool sync = ctx->sync;
	u64 id = bpf_get_current_pid_tgid();
	struct val_t *valp = bpf_map_lookup_elem(&start, &id);

	if (valp == NULL)
		return 0;

	valp->ts = bpf_ktime_get_ns();
	valp->sync = sync;
	return 0;
}

SEC("tracepoint/compaction/mm_compaction_end")
int trace_mm_compaction_end(struct trace_event_raw_mm_compaction_end *ctx)
{
	submit_event(ctx, ctx->status);
	return 0;
}

static int fragmentation_index_return(int ret)
{
	struct val_t val = { };
	u64 id = bpf_get_current_pid_tgid();

	if (target_tgid && target_tgid != (id >> 32))
		return 0;
	val.fragindex = ret;
	bpf_map_update_elem(&start, &id, &val, BPF_ANY);
	return 0;
}

SEC("kretprobe/fragmentation_index")
int BPF_KRETPROBE(kretprobe_fragmentation_index_return)
{
	return fragmentation_index_return(PT_REGS_RC(ctx));
}
SEC("fexit/fragmentation_index")
int BPF_PROG(fexit_fragmentation_index_return, struct zone *zone, unsigned int order, int ret)
{
	return fragmentation_index_return(ret);
}

char LICENSE[] SEC("license") = "GPL";
