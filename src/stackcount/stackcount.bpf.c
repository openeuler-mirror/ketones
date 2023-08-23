// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on stackcount.py - Brendan Gregg

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"
#include "stackcount.h"

const volatile pid_t target_pid = 0;
const volatile int target_cpu = -1;
const volatile bool target_per_pid = false;
const volatile bool need_kernel_stack = false;
const volatile bool need_user_stack = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, struct value_t);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stacks SEC(".maps");

static int handle_entry(void *ctx)
{
	struct key_t key = {};
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int cpu = bpf_get_smp_processor_id();

	if (target_pid && target_pid != pid)
		return 0;

	if (target_cpu != -1 && cpu != target_cpu)
		return 0;

	if (!target_per_pid) {
		key.pid = 0xffffffff;
	} else {
		key.pid = pid;
		bpf_get_current_comm(&key.name, sizeof(key.name));
	}

	if (need_kernel_stack)
		key.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
	if (need_user_stack)
		key.user_stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);

	struct value_t zero = {};
	struct value_t *val = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (!val)
		return 0;

	__sync_fetch_and_add(&val->count, 1);
	val->cpu = cpu;

	return 0;
}

SEC("kprobe.multi")
int BPF_KPROBE(function_entry)
{
	return handle_entry(ctx);
}

SEC("tracepoint")
int tracepoint_entry(void *ctx)
{
	return handle_entry(ctx);
}

SEC("uprobe")
int BPF_KPROBE(function_uprobe_entry)
{
	return handle_entry(ctx);
}

char LICENSE[] SEC("license") = "GPL";
