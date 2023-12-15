// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "offcputime.h"
#include "core_fixes.bpf.h"

#define PF_KTHREAD	0x00200000	/* Kernel thread */
#define MAX_ENTRIES	10240

const volatile bool kernel_threads_only = false;
const volatile bool user_threads_only = false;
const volatile bool user_stacks_only = false;
const volatile bool kernel_stacks_only = false;
const volatile __u64 max_block_ns = -1;
const volatile __u64 min_block_ns = -1;
const volatile pid_t target_tgid = -1;
const volatile pid_t target_pid = -1;
const volatile long state = -1;

struct internal_key {
	u64 start_ts;
	offcpu_key_t key;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct internal_key);
	__uint(max_entries, MAX_ENTRIES);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, offcpu_key_t);
	__type(value, offcpu_val_t);
	__uint(max_entries, MAX_ENTRIES);
} info SEC(".maps");

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

SEC("kprobe")
int oncpu(struct pt_regs *ctx)
{
	struct internal_key *i_keyp, i_key;
	offcpu_val_t *valp, val;
	s64 delta;
	u32 pid;
	struct task_struct *prev = (void *)PT_REGS_PARM1(ctx);

	if (allow_record(prev)) {
		pid = BPF_CORE_READ(prev, pid);
		/* To distinguish idle threads of different cores */
		if (!pid)
			pid = bpf_get_smp_processor_id();

		i_key.key.pid = pid;
		i_key.key.tgid = BPF_CORE_READ(prev, tgid);
		i_key.start_ts = bpf_ktime_get_ns();

		if (!kernel_stacks_only)
			i_key.key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
		else
			i_key.key.user_stack_id = -1;
		if (!user_stacks_only)
			i_key.key.kernel_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
		else
			i_key.key.kernel_stack_id = -1;

		bpf_map_update_elem(&start, &pid, &i_key, BPF_ANY);
		BPF_CORE_READ_STR_INTO(&val.comm, prev, comm);
		val.delta = 0;
		bpf_map_update_elem(&info, &i_key.key, &val, BPF_NOEXIST);
	}

	pid = bpf_get_current_pid_tgid();
	i_keyp = bpf_map_lookup_elem(&start, &pid);
	if (!i_keyp)
		return 0;

	delta = (s64)(bpf_ktime_get_ns() - i_keyp->start_ts);
	if (delta < 0)
		goto cleanup;
	delta /= 1000U;
	if (delta < min_block_ns || delta > max_block_ns)
		goto cleanup;
	valp = bpf_map_lookup_elem(&info, &i_keyp->key);
	if (!valp)
		goto cleanup;
	__sync_fetch_and_add(&valp->delta, delta);

cleanup:
	bpf_map_delete_elem(&start, &pid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
