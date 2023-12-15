// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on filegone.py - Curu Wong

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "filegone.h"
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
	e->action = 'D';
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->fname, sizeof(e->fname), filename);

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

SEC("tracepoint/syscalls/sys_enter_rmdir")
int tracepoint_enter_rmdir(struct trace_event_raw_sys_enter *ctx)
{
	return trace_unlink(ctx, (const char *)ctx->args[0]);
}

static int trace_rename(void *ctx, const char *old, const char *new)
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
	e->action = 'R';
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->fname, sizeof(e->fname), old);
	bpf_probe_read_user_str(&e->fname2, sizeof(e->fname2), new);

	submit_buf(ctx, e, sizeof(*e));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int tracepoint_enter_rename(struct trace_event_raw_sys_enter *ctx)
{
	return trace_rename(ctx, (const char *)ctx->args[0], (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int tracepoint_enter_renameat(struct trace_event_raw_sys_enter *ctx)
{
	return trace_rename(ctx, (const char *)ctx->args[1], (const char *)ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tracepoint_enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	return trace_rename(ctx, (const char *)ctx->args[1], (const char *)ctx->args[3]);
}

char LICENSE[] SEC("license") = "GPL";
