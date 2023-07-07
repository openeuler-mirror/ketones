// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

const volatile __u64 avenrun_kaddr = 0;

__u64 loads[3] = {};

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
	u64 *avenrun_kaddrp = (u64 *)avenrun_kaddr;

	if (avenrun_kaddr)
		bpf_core_read(&loads, sizeof(loads), avenrun_kaddrp);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
