// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on stacksnoop.py - Brendan Gregg

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "stacksnoop.h"
#include "compat.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, pid_t);
} stack_traces SEC(".maps");

const volatile pid_t target_pid = 0;

static __always_inline int trace_function_stack(void *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (target_pid && target_pid != pid)
		return 0;

	struct event *event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->pid = pid;
	event->cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	event->stack_id = bpf_get_stackid(ctx, &stack_traces, 0);

	submit_buf(ctx, event, sizeof(*event));
	return 0;
}

SEC("kprobe")
int BPF_KPROBE(kprobe_function)
{
	return trace_function_stack(ctx);
}

SEC("fentry")
int BPF_PROG(fentry_function)
{
	return trace_function_stack(ctx);
}

char LICENSE[] SEC("license") = "GPL";
