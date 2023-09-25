// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on icstat.bt - Brendan Gregg

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"
#include "icstat.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, int);
	__type(value, struct info);
} counts SEC(".maps");

SEC("kretprobe/find_inode_fast")
int BPF_KRETPROBE(find_inode_fast, int ret)
{
	struct info *infop, zero_info = {};
	int zero = 0;

	infop = bpf_map_lookup_or_try_init(&counts, &zero, &zero_info);
	if (!infop)
		return 0;

	__atomic_add_fetch(&infop->counts, 1, __ATOMIC_RELAXED);

	if (!ret)
		__atomic_add_fetch(&infop->missed, 1, __ATOMIC_RELAXED);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
