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
#include "maps.bpf.h"

const volatile pid_t target_pid = 0;

struct files {
	char fname[DNAME_INLINE_LEN];
	char fname2[DNAME_INLINE_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, struct files);
} inner_files SEC(".maps");

static int trace_enter_unlink(void *ctx, const char *filename)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct files zero = {};

	if (target_pid && target_pid != pid)
		return 0;

	struct files *f = bpf_map_lookup_or_try_init(&inner_files, &pid, &zero);
	if (!f)
		return 0;

	bpf_probe_read_user_str(f->fname, sizeof(f->fname), filename);
	return 0;
}

static int trace_exit_unlink(void *ctx, int ret)
{
	struct task_struct *task = (void *)bpf_get_current_task();
	struct event *e;
	pid_t pid = BPF_CORE_READ(task, tgid);

	struct files *f = bpf_map_lookup_and_delete_elem(&inner_files, &pid);
	if (!f)
		return 0;

	e = reserve_buf(sizeof(struct event));
	if (!e)
		return 0;

	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->action = 'D';
	e->ret = ret;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(&e->fname, f->fname, sizeof(e->fname));

	submit_buf(ctx, e, sizeof(*e));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint_enter_unlinkat(struct syscall_trace_enter *ctx)
{
	return trace_enter_unlink(ctx, (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int tracepoint_exit_unlinkat(struct syscall_trace_exit *ctx)
{
	return trace_exit_unlink(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int tracepoint_enter_unlink(struct syscall_trace_enter *ctx)
{
	return trace_enter_unlink(ctx, (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int tracepoint_exit_unlink(struct syscall_trace_exit *ctx)
{
	return trace_exit_unlink(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int tracepoint_enter_rmdir(struct syscall_trace_enter *ctx)
{
	return trace_enter_unlink(ctx, (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int tracepoint_exit_rmdir(struct syscall_trace_exit *ctx)
{
	return trace_exit_unlink(ctx, (int)ctx->ret);
}

static int trace_enter_rename(void *ctx, const char *old, const char *new)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct files zero = {};

	if (target_pid && target_pid != pid)
		return 0;

	struct files *f = bpf_map_lookup_or_try_init(&inner_files, &pid, &zero);
	if (!f)
		return 0;

	bpf_probe_read_user_str(&f->fname, sizeof(f->fname), old);
	bpf_probe_read_user_str(&f->fname2, sizeof(f->fname2), new);
	return 0;
}

static int trace_exit_rename(void *ctx, int ret)
{
	struct task_struct *task = (void *)bpf_get_current_task();
	struct event *e;
	pid_t pid = BPF_CORE_READ(task, tgid);

	struct files *f = bpf_map_lookup_and_delete_elem(&inner_files, &pid);
	if (!f)
		return 0;

	e = reserve_buf(sizeof(struct event));
	if (!e)
		return 0;

	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->action = 'R';
	e->ret = ret;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(&e->fname, &f->fname, sizeof(f->fname));
	__builtin_memcpy(&e->fname2, &f->fname2, sizeof(f->fname2));

	submit_buf(ctx, e, sizeof(*e));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int tracepoint_enter_rename(struct syscall_trace_enter *ctx)
{
	return trace_enter_rename(ctx, (const char *)ctx->args[0], (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_rename")
int tracepoint_exit_rename(struct syscall_trace_exit *ctx)
{
	return trace_exit_rename(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int tracepoint_enter_renameat(struct syscall_trace_enter *ctx)
{
	return trace_enter_rename(ctx, (const char *)ctx->args[1], (const char *)ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_exit_renameat")
int tracepoint_exit_renameat(struct syscall_trace_exit *ctx)
{
	return trace_exit_rename(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tracepoint_enter_renameat2(struct syscall_trace_enter *ctx)
{
	return trace_enter_rename(ctx, (const char *)ctx->args[1], (const char *)ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int tracepoint_exit_renameat2(struct syscall_trace_exit *ctx)
{
	return trace_exit_rename(ctx, (int)ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";
