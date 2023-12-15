// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Base on offwaketime.py - Copyright 2016 Netflix, Inc.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "offwaketime.h"
#include "core_fixes.bpf.h"
#include "maps.bpf.h"

const volatile bool user_threads_only = false;
const volatile bool kernel_threads_only = false;
const volatile bool user_stacks_only = false;
const volatile bool kernel_stacks_only = false;
const volatile pid_t target_tgid = -1;
const volatile pid_t target_pid = -1;
const volatile __u64 max_block_ns = -1;
const volatile __u64 min_block_ns = -1;
const volatile long state = -1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, u64);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct wokeby_t);
} wokeby SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

static bool allow_record(struct task_struct *task)
{
	if (target_tgid != -1 && target_tgid != BPF_CORE_READ(task, tgid))
		return false;
	if (target_pid != -1 && target_pid != BPF_CORE_READ(task, pid))
		return false;
	if (user_threads_only && BPF_CORE_READ(task, flags) & PF_KTHREAD)
		return false;
	else if (kernel_threads_only && !(BPF_CORE_READ(task, flags) & PF_KTHREAD))
		return false;
	if (state != -1 && get_task_state(task) != state)
		return false;
	return true;
}

SEC("kprobe/try_to_wake_up")
int waker(struct pt_regs *ctx)
{
	struct task_struct *p = (void *)PT_REGS_PARM1(ctx);
	u32 pid = BPF_CORE_READ(p, pid);
	struct wokeby_t woke = {};

	if (!allow_record(p))
		return 0;

	bpf_get_current_comm(&woke.name, sizeof(woke.name));

	if (!kernel_stacks_only)
		woke.u_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
	else
		woke.u_stack_id = -1;

	if (!user_stacks_only)
		woke.k_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
	else
		woke.k_stack_id = -1;

	woke.w_pid = bpf_get_current_pid_tgid();
	woke.w_tgid = bpf_get_current_pid_tgid() >> 32;

	bpf_map_update_elem(&wokeby, &pid, &woke, BPF_ANY);

	return 0;
}

SEC("kprobe")
int oncpu(struct pt_regs *ctx)
{
	u32 pid;
	u64 delta, ts, *tsp;
	struct task_struct *prev = (void *)PT_REGS_PARM1(ctx);

	/* Record timestamp for the previous Process (Process going into waiting) */
	if (allow_record(prev)) {
		pid = BPF_CORE_READ(prev, pid);
		ts = bpf_ktime_get_ns();
		bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
	}

	/* Calculate current Process's wait time by finding the timestamp of
	 * when it went into waiting.
	 */
	pid = bpf_get_current_pid_tgid();
	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp)
		return 0;
	delta = bpf_ktime_get_ns() - *tsp;
	bpf_map_delete_elem(&start, &pid);
	delta /= 1000U;
	if (delta < min_block_ns || delta > max_block_ns)
		return 0;

	struct key_t key = {0};
	struct wokeby_t *woke;

	/* create map key */
	key.t_pid = pid;
	key.t_tgid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&key.target, sizeof(key.target));

	if (!kernel_stacks_only)
		key.t_u_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
	else
		key.t_u_stack_id = -1;

	if (!user_stacks_only)
		key.t_k_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
	else
		key.t_k_stack_id = -1;

	woke = bpf_map_lookup_elem(&wokeby, &pid);
	if (woke) {
		key.w_k_stack_id = woke->k_stack_id;
		key.w_u_stack_id = woke->u_stack_id;
		key.w_pid = woke->w_pid;
		key.w_tgid = woke->w_tgid;
		__builtin_memcpy(&key.waker, woke->name, TASK_COMM_LEN);
		bpf_map_delete_elem(&wokeby, &pid);
	}

	u64 zero = 0, *count_key = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (count_key)
		__atomic_add_fetch(count_key, delta, __ATOMIC_RELAXED);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
