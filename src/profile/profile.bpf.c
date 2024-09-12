// SPDX-License-Identifier: GPL-2.0
// Copyright @ 2023 - Kylin
// Author: wolfgang huang <huangjinhui@kylinos.cn>
//
// Based on profile.py - 2016 Brendan Gregg

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "profile.h"
#include "core_fixes.bpf.h"
#include "maps.bpf.h"

#define PF_KTHREAD	0x00200000	/* Kernel thread */
#define MAX_ENTRIES	10240

const volatile bool kernel_threads_only = false;
const volatile bool user_threads_only = false;
const volatile bool filter_by_pid = false;
const volatile bool filter_by_tid = false;

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, profile_key_t);
	__type(value, u64);
	__uint(max_entries, MAX_ENTRIES);
} count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PID_NR);
	__type(key, u32);
	__type(value, u8);
} pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TID_NR);
	__type(key, u32);
	__type(value, u8);
} tids SEC(".maps");

static bool allow_record(struct task_struct *task)
{
	u32 pid = BPF_CORE_READ(task, tgid);
	u32 tid = BPF_CORE_READ(task, pid);

	/* idle thread just ignore */
	if (tid == 0)
		return false;
	if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid))
		return false;
	if (filter_by_tid && !bpf_map_lookup_elem(&tids, &tid))
		return false;
	if (user_threads_only && BPF_CORE_READ(task, flags) & PF_KTHREAD)
		return false;
	else if (kernel_threads_only && !(BPF_CORE_READ(task, flags) & PF_KTHREAD))
		return false;
	return true;
}

SEC("perf_event")
int profile_event_sample(struct bpf_perf_event_data *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	u64 zero = 0;
	u64 *valp = NULL;
	profile_key_t key = {
		.user_stack_id = -1,
		.kernel_stack_id = -1,
	};

	if (!allow_record(task))
		return 0;

	key.pid = BPF_CORE_READ(task, pid);
	key.tgid = BPF_CORE_READ(task, tgid);
	bpf_get_current_comm(&key.comm, sizeof(key.comm));

	/* not kernel thread & not only capture kernel stack */
	if (!(BPF_CORE_READ(task, flags) & PF_KTHREAD) && !kernel_threads_only)
		key.user_stack_id = bpf_get_stackid(ctx,
				&stackmap, BPF_F_USER_STACK);

	/* not only capture user stack */
	if (!user_threads_only)
		key.kernel_stack_id = bpf_get_stackid(ctx, &stackmap, 0);

	valp = bpf_map_lookup_or_try_init(&count, &key, &zero);
	if (!valp)
		return 0;

	__sync_fetch_and_add(valp, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
