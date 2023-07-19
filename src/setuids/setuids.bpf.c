// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "setuids.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240

struct data1_t {
	uid_t prev_uid;
	uid_t uid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, pid_t);
	__type(value, struct data1_t);
} birth_setuid SEC(".maps");

struct data2_t {
	uid_t prev_uid;
	uid_t ruid;
	uid_t euid;
	uid_t suid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, pid_t);
	__type(value, struct data2_t);
} birth_setreuid SEC(".maps");

static __always_inline int
handle_syscall_enter_uid_fsuid(struct trace_event_raw_sys_enter *ctx)
{
	pid_t tid = bpf_get_current_pid_tgid();
	struct data1_t data = {};

	data.prev_uid = bpf_get_current_uid_gid();
	data.uid = (uid_t)ctx->args[0];

	bpf_map_update_elem(&birth_setuid, &tid, &data, BPF_ANY);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int tracepoint_syscall_enter_setuid(struct trace_event_raw_sys_enter *ctx)
{
	return handle_syscall_enter_uid_fsuid(ctx);
}

SEC("tracepoint/syscalls/sys_enter_setfsuid")
int tracepoint_syscall_enter_setfsuid(struct trace_event_raw_sys_enter *ctx)
{
	return handle_syscall_enter_uid_fsuid(ctx);
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int tracepoint_syscall_enter_setresuid(struct trace_event_raw_sys_enter *ctx)
{
	struct data2_t data = {};
	pid_t tid = bpf_get_current_pid_tgid();

	data.prev_uid = bpf_get_current_uid_gid();
	data.ruid = (uid_t)ctx->args[0];
	data.euid = (uid_t)ctx->args[1];
	data.suid = (uid_t)ctx->args[2];

	bpf_map_update_elem(&birth_setreuid, &tid, &data, BPF_ANY);
	return 0;
}

static __always_inline int
handle_syscall_exit_uid_fsuid(struct trace_event_raw_sys_exit *ctx,
			      enum UID_TYPE type)
{
	struct event *eventp;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t tid = pid_tgid;
	pid_t pid = pid_tgid >> 32;

	struct data1_t *d = bpf_map_lookup_and_delete_elem(&birth_setuid, &tid);
	if (!d)
		return 0;

	eventp = reserve_buf(sizeof(*eventp));
	if (!eventp)
		return 0;

	eventp->pid = pid;
	bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));
	eventp->uid = d->prev_uid;
	eventp->type = type;
	eventp->setuid = d->uid;
	eventp->ret = (int)ctx->ret;

	submit_buf(ctx, eventp, sizeof(*eventp));
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_setuid")
int tracepoint_syscall_exit_setuid(struct trace_event_raw_sys_exit *ctx)
{
	return handle_syscall_exit_uid_fsuid(ctx, UID);
}

SEC("tracepoint/syscalls/sys_exit_setfsuid")
int tracepoint_syscall_exit_setfsuid(struct trace_event_raw_sys_exit *ctx)
{
	return handle_syscall_exit_uid_fsuid(ctx, FSUID);
}

SEC("tracepoint/syscalls/sys_exit_setreuid")
int tracepoint_syscall_exit_setreuid(struct trace_event_raw_sys_exit *ctx)
{
	struct event *eventp;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t tid = pid_tgid;
	pid_t pid = pid_tgid >> 32;

	struct data2_t *d = bpf_map_lookup_and_delete_elem(&birth_setreuid, &tid);
	if (!d)
		return 0;

	eventp = reserve_buf(sizeof(*eventp));
	if (!eventp)
		return 0;

	eventp->pid = pid;
	bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));
	eventp->uid = d->prev_uid;
	eventp->type = REUID;
	eventp->ruid = d->ruid;
	eventp->euid = d->euid;
	eventp->suid = d->suid;
	eventp->ret = (int)ctx->ret;

	submit_buf(ctx, eventp, sizeof(*eventp));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
