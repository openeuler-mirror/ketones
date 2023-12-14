// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "filesnoop.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

const volatile __u64 target_filename_sz = 0;
const volatile bool filter_filename = false;
const volatile int target_op = F_NONE;

#define MAX_ENTRIES	1024

char target_filename[FSFILENAME_MAX] = {};

struct key_t {
	pid_t tid;
	int   fd;
};

struct fsfilename {
	char name[FSFILENAME_MAX];
};

struct print_value {
	struct key_t key;
	struct fsfilename *filename;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, struct fsfilename);
} files SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, pid_t);
	__type(value, struct fsfilename);
} opens SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, pid_t);
	__type(value, struct print_value);
} prints SEC(".maps");

/* Filter filename */
static __always_inline bool filename_matched(const char *filename)
{
	if (!filter_filename)
		return true;

	for (int i = 0; i < target_filename_sz && i < FSFILENAME_MAX ; i++) {
		if (filename[i] != target_filename[i])
			return false;
	}

	return true;
}

/* Filter target operation */
static __always_inline bool is_target_operation(enum file_op op)
{
	switch (target_op) {
	case F_READ:
	case F_READV:
		return op == F_READ || op == F_READV;
	case F_WRITE:
	case F_WRITEV:
		return op == F_WRITE || op == F_WRITEV;
	case F_RENAMEAT:
	case F_RENAMEAT2:
		return op == F_RENAMEAT || op == F_RENAMEAT2;
	case F_UNLINKAT:
		return op == F_UNLINKAT;
	case F_CLOSE:
		return op == F_CLOSE;
	case F_UTIMENSAT:
		return op == F_UTIMENSAT;
	}

	return true;
}

static __always_inline int
handle_file_syscall_open_enter(struct trace_event_raw_sys_enter *ctx, enum file_op op)
{
	struct fsfilename filename = {};

	if (filter_filename && target_filename_sz == 0)
		return 0;

	pid_t tid = bpf_get_current_pid_tgid();

	if (op == F_OPENAT || op == F_OPENAT2)
		bpf_probe_read_user_str(&filename.name, FSFILENAME_MAX, (const char *)ctx->args[1]);
	else
		bpf_probe_read_user_str(&filename.name, FSFILENAME_MAX, (const char *)ctx->args[0]);

	/* If not match name, everything is over */
	if (!filename_matched(filename.name))
		return 0;

	bpf_map_update_elem(&opens, &tid, &filename, BPF_ANY);
	return 0;
}

static __always_inline int
handle_file_syscall_open_exit(struct trace_event_raw_sys_exit *ctx, enum file_op op)
{
	struct task_struct *task = (void *)bpf_get_current_task();
	pid_t tid = BPF_CORE_READ(task, pid);
	struct fsfilename *filename;
	int fd = ctx->ret;

	filename = bpf_map_lookup_and_delete_elem(&opens, &tid);
	if (!filename)
		return 0;

	/* make sure open is not failed and not only filter open syscall*/
	if (fd >= 0 && !is_target_operation(op)) {
		struct key_t key = { .tid = tid, .fd = fd, };
		bpf_map_update_elem(&files, &key, filename, BPF_ANY);
	}

	return 0;
}

static __always_inline int
handle_file_syscall_enter(void *ctx, enum file_op op, int fd)
{
	pid_t tid = bpf_get_current_pid_tgid();
	struct key_t key = {
		.tid = tid,
		.fd  = fd,
	};

	/* I'm not the open one */
	struct fsfilename *filename = bpf_map_lookup_elem(&files, &key);
	if (!filename)
		return 0;

	/* F_CLOSE is for cleanup maps */
	if (!is_target_operation(op) && op != F_CLOSE)
		return 0;

	/* Record print values */
	struct print_value value = {
		.key = key,
		.filename = filename,
	};

	bpf_map_update_elem(&prints, &tid, &value, BPF_ANY);
	return 0;
}
static __always_inline int
handle_file_syscall_exit(void *ctx, enum file_op op, int ret)
{
	struct task_struct *task = (void *)bpf_get_current_task();
	pid_t tid = BPF_CORE_READ(task, pid);
	struct event *event;

	/* Not record by enter */
	struct print_value *val = bpf_map_lookup_and_delete_elem(&prints, &tid);
	if (!val)
		return 0;

	/* Only F_CLOSE, target_op can arrive here */
	if (is_target_operation(op)) {
		event = reserve_buf(sizeof(*event));
		if (!event)
			return 0;

		bpf_probe_read(&event->filename, sizeof(event->filename),
			       &val->filename->name);

		event->pid = BPF_CORE_READ(task, tgid);
		event->ppid = BPF_CORE_READ(task, real_parent, tgid);
		bpf_get_current_comm(&event->comm, sizeof(event->comm));
		event->op = op;
		event->ret = ret;
		event->fd = val->key.fd;

		submit_buf(ctx, event, sizeof(*event));
	}

	/* value->filename is pointer of files map, we must delete
	 * files map after CLOSE operation finish
	 */
	if (op == F_CLOSE)
		bpf_map_delete_elem(&files, &val->key);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint_sys_enter_open(struct trace_event_raw_sys_enter *ctx)
{
	return handle_file_syscall_open_enter(ctx, F_OPEN);
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint_sys_exit_open(struct trace_event_raw_sys_exit *ctx)
{
	return handle_file_syscall_open_exit(ctx, F_OPEN);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_file_syscall_open_enter(ctx, F_OPENAT);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint_sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_file_syscall_open_exit(ctx, F_OPENAT);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tracepoint_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx)
{
	return handle_file_syscall_open_enter(ctx, F_OPENAT2);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int tracepoint_sys_exit_openat2(struct trace_event_raw_sys_exit *ctx)
{
	return handle_file_syscall_open_exit(ctx, F_OPENAT2);
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	return handle_file_syscall_enter(ctx, F_WRITE, (int)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	return handle_file_syscall_exit(ctx, F_WRITE, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_writev")
int tracepoint_sys_enter_writev(struct trace_event_raw_sys_enter *ctx)
{
	return handle_file_syscall_enter(ctx, F_WRITEV, (int)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_writev")
int tracepoint_sys_exit_writev(struct trace_event_raw_sys_exit *ctx)
{
	return handle_file_syscall_exit(ctx, F_WRITEV, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	return handle_file_syscall_enter(ctx, F_READ, (int)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	return handle_file_syscall_exit(ctx, F_READ, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_readv")
int tracepoint_sys_enter_readv(struct trace_event_raw_sys_enter *ctx)
{
	return handle_file_syscall_enter(ctx, F_READV, (int)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_readv")
int tracepoint_sys_exit_readv(struct trace_event_raw_sys_exit *ctx)
{
	return handle_file_syscall_exit(ctx, F_READV, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint_sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_file_syscall_enter(ctx, F_UNLINKAT, (int)ctx->args[0]);
}
SEC("tracepoint/syscalls/sys_exit_unlinkat")
int tracepoint_sys_exit_unlinkat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_file_syscall_exit(ctx, F_UNLINKAT, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int tracepoint_sys_enter_renameat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_file_syscall_enter(ctx, F_RENAMEAT, (int)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_renameat")
int tracepoint_sys_exit_renameat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_file_syscall_exit(ctx, F_RENAMEAT, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tracepoint_sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	return handle_file_syscall_enter(ctx, F_RENAMEAT2, (int)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int tracepoint_sys_exit_renameat2(struct trace_event_raw_sys_exit *ctx)
{
	return handle_file_syscall_exit(ctx, F_RENAMEAT2, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint_sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
	return handle_file_syscall_enter(ctx, F_CLOSE, (int)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_close")
int tracepoint_sys_exit_close(struct trace_event_raw_sys_exit *ctx)
{
	return handle_file_syscall_exit(ctx, F_CLOSE, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_utimensat")
int tracepoint_sys_enter_utimensat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_file_syscall_enter(ctx, F_UTIMENSAT, (int)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_utimensat")
int tracepoint_sys_exit_utimensat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_file_syscall_exit(ctx, F_UTIMENSAT, ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";
