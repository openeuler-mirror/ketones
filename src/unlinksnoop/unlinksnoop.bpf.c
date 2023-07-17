// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "unlinksnoop.h"
#include "compat.bpf.h"

const volatile pid_t target_pid = 0;

static int trace_unlink(void *ctx, const char *filename)
{
	struct task_struct *task = (void *)bpf_get_current_task();
	struct event *e;
	pid_t pid = BPF_CORE_READ(task, tgid);

	if (target_pid && target_pid != pid)
		return 0;

	e = reserve_buf(sizeof(struct event));
	if (!e)
		return 0;

	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	submit_buf(ctx, e, sizeof(*e));

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	return trace_unlink(ctx, (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int tracepoint_enter_unlink(struct trace_event_raw_sys_enter *ctx)
{
	return trace_unlink(ctx, (const char *)ctx->args[0]);
}

char LICENSE[] SEC("license") = "GPL";
