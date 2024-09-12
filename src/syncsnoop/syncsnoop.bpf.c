// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syncsnoop.h"
#include "compat.bpf.h"

static __always_inline int handle_enter_sync(void *ctx, int sys)
{
	struct event *event;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->ts_us = bpf_ktime_get_ns() / 1000;
	event->sys = sys;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	submit_buf(ctx, event, sizeof(*event));

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync")
int tracepoint_sys_enter_sync(struct syscall_trace_enter *ctx)
{
	return handle_enter_sync(ctx, SYS_SYNC);
}

SEC("tracepoint/syscalls/sys_enter_syncfs")
int tracepoint_sys_enter_syncfs(struct syscall_trace_enter *ctx)
{
	return handle_enter_sync(ctx, SYS_SYNCFS);
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int tracepoint_sys_enter_fsync(struct syscall_trace_enter *ctx)
{
	return handle_enter_sync(ctx, SYS_FSYNC);
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int tracepoint_sys_enter_fdatasync(struct syscall_trace_enter *ctx)
{
	return handle_enter_sync(ctx, SYS_FDATASYNC);
}

SEC("tracepoint/syscalls/sys_enter_sync_file_range")
int tracepoint_sys_enter_sync_file_range(struct syscall_trace_enter *ctx)
{
	return handle_enter_sync(ctx, SYS_SYNC_FILE_RANGE);
}

SEC("tracepoint/syscalls/sys_enter_msync")
int tracepoint_sys_enter_msync(struct syscall_trace_enter *ctx)
{
	return handle_enter_sync(ctx, SYS_MSYNC);
}

char LICENSE[] SEC("license") = "GPL";
