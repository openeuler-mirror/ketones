// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "naptime.h"
#include "compat.bpf.h"

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int tracepoint__sys_enter_nanosleep(struct trace_event_raw_sys_enter *ctx)
{
	struct __kernel_timespec *rqtp = (struct __kernel_timespec *)(ctx->args[0]);
	struct event *event;

	__kernel_time64_t tv_sec = BPF_CORE_READ_USER(rqtp, tv_sec);
	long long tv_nsec = BPF_CORE_READ_USER(rqtp, tv_nsec);

	if ((tv_sec + tv_nsec) == 0)
		return 0;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	event->ppid = BPF_CORE_READ(task, real_parent, pid);
	event->pid = bpf_get_current_pid_tgid() >> 32;
	BPF_CORE_READ_STR_INTO(&event->pcomm, task, real_parent, comm);
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	event->tv_sec = tv_sec;
	event->tv_nsec = tv_nsec;

	submit_buf(ctx, event, sizeof(*event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
