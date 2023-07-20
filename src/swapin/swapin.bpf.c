// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "swapin.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, u64);
} counts SEC(".maps");

static __always_inline int handle_swap_readpage(void)
{
	u64 *valp, zero = 0;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (target_pid && target_pid != pid)
		return 0;

	struct key_t key = {
		.pid = pid
	};
	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (!valp)
		return 0;

	__sync_fetch_and_add(valp, 1);

	return 0;
}

SEC("kprobe/swap_readpage")
int BPF_KPROBE(swap_readpage_kprobe)
{
	return handle_swap_readpage();
}

SEC("fentry/swap_readpage")
int BPF_PROG(swap_readpage_fentry)
{
	return handle_swap_readpage();
}

char LICENSE[] SEC("license") = "GPL";
