// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u64 counts = 0;

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_process_fork)
{
	__sync_fetch_and_add(&counts, 1);
	return 0;
}

SEC("raw_tp/sched_process_fork")
int BPF_PROG(sched_process_fork_raw)
{
	__sync_fetch_and_add(&counts, 1);
	return 0;
}

char LICENCE[] SEC("license") = "GPL";
