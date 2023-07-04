// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bitesize.h"
#include "bits.bpf.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

const volatile char target_comm[TASK_COMM_LEN] = {};
const volatile bool filter_dev = false;
const volatile __u32 target_dev = 0;

extern __u32 LINUX_KERNEL_VERSION __kconfig;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

static __always_inline bool comm_allowed(const char *comm)
{
	for (int i = 0; target_comm[i] != '\0' && i < TASK_COMM_LEN; i++) {
		if (comm[i] != target_comm[i])
			return false;
	}

	return true;
}

static __always_inline int trace_rq_issue(struct request *rq)
{
	struct hist_key hkey;
	struct hist *histp;
	u64 slot;

	if (filter_dev) {
		struct gendisk *disk = get_disk(rq);
		u32 dev;

		dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
				   BPF_CORE_READ(disk, first_minor)) : 0;
		if (target_dev != dev)
			return 0;
	}

	bpf_get_current_comm(&hkey.comm, sizeof(hkey.comm));
	if (!comm_allowed(hkey.comm))
		return 0;

	histp = bpf_map_lookup_or_try_init(&hists, &hkey, &zero);
	if (!histp)
		return 0;

	slot = log2l(BPF_CORE_READ(rq, __data_len) / 1024);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);

	return 0;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_rq_issue)
{
	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 11, 0))
		return trace_rq_issue((void *)ctx[0]);
	else
		return trace_rq_issue((void *)ctx[1]);
}

SEC("raw_tp/block_rq_issue")
int BPF_PROG(block_rq_issue_raw)
{
	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 11, 0))
		return trace_rq_issue((void *)ctx[0]);
	else
		return trace_rq_issue((void *)ctx[1]);
}

char LICENSE[] SEC("license") = "GPL";
