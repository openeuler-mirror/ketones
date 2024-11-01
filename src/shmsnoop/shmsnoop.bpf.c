// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "shmsnoop.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"
#include "compat.bpf.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;
const volatile pid_t target_tid = 0;

static const struct event zero;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, pid_t);
	__type(value, struct event);
} values SEC(".maps");

static __always_inline int probe_entry(struct syscall_trace_enter *ctx, int sys_type)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	pid_t tid = id;
	struct event *event;

	if (target_pid && target_pid != pid)
		return 0;

	if (target_tid && target_tid != tid)
		return 0;

	event = bpf_map_lookup_or_try_init(&values, &pid, &zero);
	if (!event)
		return 0;

	event->pid = pid;
	event->tid = tid;
	event->sys = sys_type;

	switch (sys_type) {
	case SYS_SHMGET:
		event->key = (unsigned long)ctx->args[0];
		event->size = (unsigned long)ctx->args[1];
		event->shmflg = (unsigned long)ctx->args[2];
		break;
	case SYS_SHMAT:
		event->shmid = (unsigned long)ctx->args[0];
		event->shmaddr = (unsigned long)ctx->args[1];
		event->shmflg = (unsigned long)ctx->args[2];
		break;
	case SYS_SHMDT:
		event->shmaddr = (unsigned long)ctx->args[0];
		break;
	case SYS_SHMCTL:
		event->shmid = (unsigned long)ctx->args[0];
		event->cmd = (unsigned long)ctx->args[1];
		event->buf = (unsigned long)ctx->args[2];
		break;
	}

	return 0;
}

static __always_inline int probe_return(struct syscall_trace_exit *ctx, unsigned long ret)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	pid_t tid = id;
	struct event *event, *e;

	if (target_pid && target_pid != pid)
		return 0;

	if (target_tid && target_tid != tid)
		return 0;

	event = bpf_map_lookup_and_delete_elem(&values, &pid);
	if (!event)
		return 0;

	e = reserve_buf(sizeof(struct event));
	if (!e)
		return 0;

	__builtin_memcpy(e, event, sizeof(struct event));
	e->ret = ret;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	submit_buf(ctx, e, sizeof(struct event));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmat")
int handle_shmat_entry(struct syscall_trace_enter *ctx)
{
	return probe_entry(ctx, SYS_SHMAT);
}

SEC("tracepoint/syscalls/sys_exit_shmat")
int handle_shmat_return(struct syscall_trace_exit *ctx)
{
	return probe_return(ctx, (unsigned long)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_shmctl")
int handle_shmctl_entry(struct syscall_trace_enter *ctx)
{
	return probe_entry(ctx, SYS_SHMCTL);
}

SEC("tracepoint/syscalls/sys_exit_shmctl")
int handle_shmctl_return(struct syscall_trace_exit *ctx)
{
	return probe_return(ctx, (unsigned long)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_shmdt")
int handle_shmdt_entry(struct syscall_trace_enter *ctx)
{
	return probe_entry(ctx, SYS_SHMDT);
}

SEC("tracepoint/syscalls/sys_exit_shmdt")
int handle_shmdt_return(struct syscall_trace_exit *ctx)
{
	return probe_return(ctx, (unsigned long)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_shmget")
int handle_shmget_entry(struct syscall_trace_enter *ctx)
{
	return probe_entry(ctx, SYS_SHMGET);
}

SEC("tracepoint/syscalls/sys_exit_shmget")
int handle_shmget_return(struct syscall_trace_exit *ctx)
{
	return probe_return(ctx, (unsigned long)ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";
