// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syncsnoop.h"
#include "compat.bpf.h"

static __always_inline int handle_enter_sync(void *ctx, const char *funcname)
{
	struct event *event;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	bpf_core_read_str(&event->funcname, sizeof(event->funcname), funcname);

	submit_buf(ctx, event, sizeof(*event));

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync")
int tracepoint_sys_enter_sync(struct trace_event_raw_sys_enter *ctx)
{
	return handle_enter_sync(ctx, "tracepoint:syscalls:sys_enter_sync");
}

SEC("tracepoint/syscalls/sys_enter_syncfs")
int tracepoint_sys_enter_syncfs(struct trace_event_raw_sys_enter *ctx)
{
	return handle_enter_sync(ctx, "tracepoint:syscalls:sys_enter_syncfs");
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int tracepoint_sys_enter_fsync(struct trace_event_raw_sys_enter *ctx)
{
	return handle_enter_sync(ctx, "tracepoint:syscalls:sys_enter_fsync");
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int tracepoint_sys_enter_fdatasync(struct trace_event_raw_sys_enter *ctx)
{
	return handle_enter_sync(ctx, "tracepoint:syscalls:sys_enter_fdatasync");
}

SEC("tracepoint/syscalls/sys_enter_sync_file_range")
int tracepoint_sys_enter_sync_file_range(struct trace_event_raw_sys_enter *ctx)
{
	return handle_enter_sync(ctx, "tracepoint:syscalls:sys_enter_sync_file_range");
}

SEC("tracepoint/syscalls/sys_enter_msync")
int tracepoint_sys_enter_msync(struct trace_event_raw_sys_enter *ctx)
{
	return handle_enter_sync(ctx, "tracepoint:syscalls:sys_enter_msync");
}

char LICENSE[] SEC("license") = "GPL";
