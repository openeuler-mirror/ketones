// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "opensnoop.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "compat.bpf.h"
#include "maps.bpf.h"

const volatile pid_t target_pid = 0;
const volatile pid_t target_tgid = 0;
const volatile uid_t target_uid = 0;
const volatile bool target_failed = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct args_t);
} start SEC(".maps");

static __always_inline bool valid_uid(uid_t uid)
{
	return uid != INVALID_UID;
}

static __always_inline bool trace_allowed(u32 tgid, u32 pid)
{
	if (target_pid && target_pid != pid)
		return false;
	if (target_tgid && target_tgid != tgid)
		return false;
	if (valid_uid(target_uid)) {
		uid_t uid = (u32)bpf_get_current_uid_gid();

		if (target_uid != uid)
			return false;
	}
	return true;
}

static __always_inline
int record_args(const char *fname, int flags, umode_t modes)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t tgid = id >> 32;
	pid_t pid = (pid_t)id;

	if (trace_allowed(tgid, pid)) {
		struct args_t args = {};

		args.fname = fname;
		args.flags = flags;
		args.modes = modes;
		bpf_map_update_elem(&start, &pid, &args, BPF_ANY);
	}

	return 0;
}

static __always_inline int trace_exit(struct syscall_trace_exit *ctx)
{
	struct event *eventp;
	struct args_t *argsp;
	uintptr_t stack[3];
	int ret;
	struct task_struct *task = (void *)bpf_get_current_task();
	pid_t pid = BPF_CORE_READ(task, pid);

	argsp = bpf_map_lookup_and_delete_elem(&start, &pid);
	if (!argsp)
		return 0;

	ret = ctx->ret;
	if (target_failed && ret >= 0)
		return 0;

	eventp = reserve_buf(sizeof(*eventp));
	if (!eventp)
		return 0;

	eventp->pid = BPF_CORE_READ(task, tgid);
	eventp->ppid = BPF_CORE_READ(task, real_parent, tgid);
	eventp->uid = (uid_t)bpf_get_current_uid_gid();
	bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));
	bpf_probe_read_user_str(&eventp->fname, sizeof(eventp->fname), argsp->fname);
	eventp->flags = argsp->flags;
	eventp->modes = argsp->modes;
	eventp->ret = ret;

	bpf_get_stack(ctx, &stack, sizeof(stack), BPF_F_USER_STACK);
	/* Skip the first address that is usually the syscall it-self */
	eventp->callers[0] = stack[1];
	eventp->callers[1] = stack[2];

	submit_buf(ctx, eventp, sizeof(*eventp));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct syscall_trace_enter *ctx)
{
	return record_args((const char *)ctx->args[0], (int)ctx->args[1],
			   (umode_t)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct syscall_trace_enter *ctx)
{
	return record_args((const char *)ctx->args[1], (int)ctx->args[2],
			   (umode_t)ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";
