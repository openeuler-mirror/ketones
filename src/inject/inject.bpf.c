// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <asm-generic/errno-base.h>
#include "maps.bpf.h"
#include "inject.h"

const volatile __u64 max_stack_depth = 0;
const volatile int max_err_count = 0;
const volatile __u32 probability = 0;
const volatile __u32 enable_flag = 0;
const volatile enum inject_mode mode = 0;

struct pid_struct {
	__u64 curr_call; /* book keeping to handle recursion */
	__u64 conds_met; /* stack pointer */
	__u64 stack[STACK_MAX_DEPTH];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400);
	__type(key, __u32);
	__type(value, struct pid_struct);
} m SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, int);
} count SEC(".maps");

#define CALL_DEPTH_ENTRY(dp)						\
SEC("kprobe")								\
int call_depth_entry_##dp(struct pt_regs *ctx)				\
{									\
	__u32 pid = bpf_get_current_pid_tgid();				\
	struct pid_struct p_struct = {0, 0};				\
	struct pid_struct *p;						\
									\
	if (dp == max_stack_depth - 1 && probability < 0xFFFFFF00) {	\
		if (bpf_get_prandom_u32() > probability)		\
			return 0;					\
	}								\
	p = bpf_map_lookup_or_try_init(&m, &pid, &p_struct);		\
	if (!p)								\
		return 0;						\
	if (p->conds_met >= max_stack_depth)				\
		return 0;						\
	if (p->conds_met == max_stack_depth - dp - 1 && (enable_flag &	\
		(0x1 << dp)) && max_stack_depth >= dp) {		\
		p->stack[max_stack_depth - dp] = p->curr_call;		\
		p->conds_met++;						\
	}								\
	p->curr_call++;							\
	return 0;							\
}

#define CALL_DEPTH_EXIT(dp)						\
SEC("kretprobe")							\
int call_depth_exit_##dp(struct pt_regs *ctx)				\
{									\
	__u32 pid = bpf_get_current_pid_tgid();				\
	struct pid_struct *p;						\
									\
	p = bpf_map_lookup_elem(&m, &pid);				\
	if (!p)								\
		return 0;						\
	p->curr_call--;							\
	if (p->conds_met < 1 || p->conds_met > max_stack_depth)		\
		return 0;						\
	if (p->conds_met - 1 > STACK_MAX_DEPTH)				\
		return 0;						\
	if (p->stack[p->conds_met] == p->curr_call)			\
		p->conds_met--;						\
	if (dp == max_stack_depth - 1)					\
		bpf_map_delete_elem(&m, &pid);				\
	return 0;							\
}

CALL_DEPTH_ENTRY(1)
CALL_DEPTH_ENTRY(2)
CALL_DEPTH_ENTRY(3)
CALL_DEPTH_ENTRY(4)
CALL_DEPTH_ENTRY(5)
CALL_DEPTH_ENTRY(6)
CALL_DEPTH_ENTRY(7)
CALL_DEPTH_ENTRY(8)

CALL_DEPTH_EXIT(1)
CALL_DEPTH_EXIT(2)
CALL_DEPTH_EXIT(3)
CALL_DEPTH_EXIT(4)
CALL_DEPTH_EXIT(5)
CALL_DEPTH_EXIT(6)
CALL_DEPTH_EXIT(7)
CALL_DEPTH_EXIT(8)

static __always_inline int do_error_inject(struct pt_regs *ctx, int err)
{
	struct pid_struct *p;
	struct pid_struct p_struct = {};
	__u32 overridden = 0;
	__u32 pid = bpf_get_current_pid_tgid();
	int zero = 0;
	__u32 *val;

	if (!err)
		return 0;

	val = bpf_map_lookup_elem(&count, &zero);
	if (val)
		overridden = *val;

	/*
	 * If this is the only call in the chain and predicate passes
	 */
	if (max_stack_depth == 1 && (enable_flag & 0x1) &&
		overridden < max_err_count) {
		__atomic_add_fetch(&val, 1, __ATOMIC_RELAXED);
		bpf_override_return(ctx, err);
		return 0;
	}

	p = bpf_map_lookup_or_try_init(&m, &pid, &p_struct);
	if (!p)
		return 0;

	/*
	 * If all conds have been met and predicate passes
	 */
	if (p->conds_met == max_stack_depth - 1 && (enable_flag & 0x1) &&
		overridden < max_err_count) {
		__atomic_add_fetch(&val, 1, __ATOMIC_RELAXED);
		bpf_override_return(ctx, err);
		overridden++;
		bpf_map_update_elem(&count, &zero, &overridden, BPF_EXIST);
	}

	return 0;
}

SEC("kprobe")
int should_failslab_entry(struct pt_regs *ctx)
{
	return do_error_inject(ctx, -ENOMEM);
}

SEC("kprobe")
int should_fail_bio_entry(struct pt_regs *ctx)
{
	return do_error_inject(ctx, -EIO);
}

SEC("kprobe")
int should_fail_alloc_page_entry(struct pt_regs *ctx)
{
	return do_error_inject(ctx, true);
}

char LICENSE[] SEC("license") = "GPL";
