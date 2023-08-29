// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Base on trace.py - Copyright (C) 2016 Sasha Goldshtein.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"
#include "trace.h"

const volatile pid_t target_pid = 0;
const volatile pid_t target_tid = 0;
const volatile int target_cpu = -1;
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

static int handle_entry(void *ctx, int type)
{
	struct key_t key = {};
	pid_t tid = bpf_get_current_pid_tgid();
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (target_pid && target_pid != pid)
		return 0;

	if (target_tid && target_tid != tid)
		return 0;

	key.pid = pid;
	key.tid = tid;
	key.uid = (unsigned)(bpf_get_current_uid_gid() & 0xffffffff);
	key.gid = (unsigned)(bpf_get_current_uid_gid() >> 32);
	key.cpu = bpf_get_smp_processor_id();
	key.task = (struct task_struct *)bpf_get_current_task();
	bpf_get_current_comm(&key.comm, sizeof(key.comm));

	if (type == UPROBE || type == KPROBE) {
		key.args[0] = PT_REGS_PARM1((struct pt_regs *)ctx);
		key.args[1] = PT_REGS_PARM2((struct pt_regs *)ctx);
		key.args[2] = PT_REGS_PARM3((struct pt_regs *)ctx);
		key.args[3] = PT_REGS_PARM4((struct pt_regs *)ctx);
		key.args[4] = PT_REGS_PARM5((struct pt_regs *)ctx);
		key.args[5] = PT_REGS_PARM6((struct pt_regs *)ctx);
		key.retval = PT_REGS_RC((struct pt_regs *)ctx);
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

	return 0;
}

SEC("kprobe")
int BPF_KPROBE(function_entry)
{
	return handle_entry(ctx, KPROBE);
}

SEC("tracepoint")
int tracepoint_entry(void *ctx)
{
	return handle_entry(ctx, TRACEPOINT);
}

SEC("uprobe")
int BPF_UPROBE(function_uprobe_entry)
{
	return handle_entry(ctx, UPROBE);
}

char LICENSE[] SEC("license") = "GPL";
