// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "cpudist.h"
#include "bits.bpf.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

#define TASK_RUNNING	0

const volatile bool filter_memcg = false;
const volatile bool target_per_process = false;
const volatile bool target_per_thread = false;
const volatile bool target_offcpu = false;
const volatile bool target_ms = false;
const volatile pid_t target_tgid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

static struct hist zero;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct hist);
} hists SEC(".maps");

static __always_inline void store_start(u32 tgid, u32 pid, u64 ts)
{
	if (target_tgid != -1 && target_tgid != tgid)
		return;

	bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
}

static __always_inline void update_hist(struct task_struct *p, u32 tgid,
					u32 pid, u64 ts)
{
	u64 delta, *tsp, slot;
	struct hist *histp;
	u32 id;

	if (target_tgid != -1 && target_tgid != tgid)
		return;

	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp || ts < *tsp)
		return;

	if (target_per_process)
		id = tgid;
	else if (target_per_thread)
		id = pid;
	else
		id = -1;

	histp = bpf_map_lookup_or_try_init(&hists, &id, &zero);
	if (!histp)
		return;

	BPF_CORE_READ_STR_INTO(&histp->comm, p, comm);
	delta = ts - *tsp;
	if (target_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	__sync_fetch_and_add(&histp->slots[slot], 1);
}

static int handle_switch(struct task_struct *prev, struct task_struct *next)
{
	u32 prev_tgid = BPF_CORE_READ(prev, tgid);
	u32 prev_pid = BPF_CORE_READ(prev, pid);
	u32 tgid = BPF_CORE_READ(next, tgid);
	u32 pid = BPF_CORE_READ(next, pid);
	u64 ts;

	if (filter_memcg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	ts = bpf_ktime_get_ns();
	if (target_offcpu) {
		store_start(prev_tgid, prev_pid, ts);
		update_hist(next, tgid, pid, ts);
	} else {
		if (get_task_state(prev) == TASK_RUNNING)
			update_hist(prev, prev_tgid, prev_pid, ts);
		store_start(tgid, pid, ts);
	}
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_btf, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return handle_switch(prev, next);
}

SEC("raw_tp/sched_switch")
int BPF_PROG(sched_switch_raw, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return handle_switch(prev, next);
}

char LICENSE[] SEC("license") = "GPL";
