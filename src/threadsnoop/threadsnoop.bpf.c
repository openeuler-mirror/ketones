// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "threadsnoop.h"
#include "compat.bpf.h"

SEC("uprobe")
int BPF_KPROBE(pthread_create, void *arg1, void *arg2, void *(*start)(void *))
{
	struct event *event;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	event->function_addr = (__u64)start;
	submit_buf(ctx, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
