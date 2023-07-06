// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Based on funcslower.py - Copyright 2017, Sasha Goldshtein

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "compat.bpf.h"
#include "funcslower.h"

const volatile pid_t target_pid = 0;
const volatile bool need_grab_args = false;
const volatile bool need_user_stack = false;
const volatile bool need_kernel_stack = false;
const volatile __u64 duration_ns = 0;

struct entry_t {
	__u64 id;
	__u64 start_ns;
	__u64 args[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct entry_t);
} entryinfo SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, __u32);
} stack_trace SEC(".maps");

static __always_inline int trace_entry(struct pt_regs *ctx, int id)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t pid = pid_tgid >> 32;

	if (target_pid && target_pid != pid)
		return 0;

	struct entry_t entry = {};
	entry.start_ns = bpf_ktime_get_ns();
	entry.id = id;

	if (need_grab_args) {
		entry.args[0] = PT_REGS_PARM1(ctx);
		entry.args[1] = PT_REGS_PARM2(ctx);
		entry.args[2] = PT_REGS_PARM3(ctx);
		entry.args[3] = PT_REGS_PARM4(ctx);
		entry.args[4] = PT_REGS_PARM5(ctx);
	}

	bpf_map_update_elem(&entryinfo, &pid_tgid, &entry, BPF_ANY);
	return 0;
}

static int trace_return(struct pt_regs *ctx, bool kprobe)
{
	struct entry_t *entryp;
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	entryp = bpf_map_lookup_elem(&entryinfo, &pid_tgid);
	if (!entryp)
		return 0;

	s64 delta_ns = bpf_ktime_get_ns() - entryp->start_ns;
	if (delta_ns < 0 || delta_ns < duration_ns)
		return 0;

	struct event *event = reserve_buf(sizeof(struct event));
	if (!event)
		return 0;

	event->id = entryp->id;
	event->pid_tgid = pid_tgid;
	event->duration_ns = delta_ns;
	event->retval = PT_REGS_RC(ctx);
	event->user_stack_id = -1;
	event->kernel_stack_id = -1;

	if (need_user_stack)
		event->user_stack_id = bpf_get_stackid(ctx, &stack_trace, BPF_F_USER_STACK);
	if (need_kernel_stack && kprobe)
		event->kernel_stack_id = bpf_get_stackid(ctx, &stack_trace, 0);
	if (need_grab_args)
		bpf_probe_read(event->args, sizeof(event->args), entryp->args);
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	submit_buf(ctx, event, sizeof(*event));
	return 0;
}

SEC("kretprobe")
int trace_return_k(struct pt_regs *ctx)
{
	return trace_return(ctx, true);
}

SEC("uretprobe")
int trace_return_u(struct pt_regs *ctx)
{
	return trace_return(ctx, false);
}

#define TRACE_FUNCTION_K(id)	\
SEC("?kprobe") int trace_k##id(struct pt_regs *ctx)	\
{ \
	return trace_entry(ctx, id);	\
}

#define TRACE_FUNCTION_U(id)	\
SEC("?uprobe") int trace_u##id(struct pt_regs *ctx)	\
{ \
	return trace_entry(ctx, id);	\
}

TRACE_FUNCTION_K(0)
TRACE_FUNCTION_K(1)
TRACE_FUNCTION_K(2)
TRACE_FUNCTION_K(3)
TRACE_FUNCTION_K(4)
TRACE_FUNCTION_K(5)
TRACE_FUNCTION_K(6)
TRACE_FUNCTION_K(7)
TRACE_FUNCTION_K(8)
TRACE_FUNCTION_K(9)

TRACE_FUNCTION_U(0)
TRACE_FUNCTION_U(1)
TRACE_FUNCTION_U(2)
TRACE_FUNCTION_U(3)
TRACE_FUNCTION_U(4)
TRACE_FUNCTION_U(5)
TRACE_FUNCTION_U(6)
TRACE_FUNCTION_U(7)
TRACE_FUNCTION_U(8)
TRACE_FUNCTION_U(9)

char LICENSE[] SEC("license") = "GPL";
