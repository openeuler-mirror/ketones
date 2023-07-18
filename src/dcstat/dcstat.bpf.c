// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on dcstat.py - Brendan Gregg

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "dcstat.h"

__u64 stats[S_MAXSTAT] = {};

static __always_inline int inc_stats(int key)
{
	__atomic_add_fetch(&stats[key], 1, __ATOMIC_RELAXED);
	return 0;
}

SEC("kprobe/lookup_fast")
int BPF_KPROBE(lookup_fast_kprobe, struct nameidata *nd, struct path *path)
{
	return inc_stats(S_REFS);
}

SEC("fentry/lookup_fast")
int BPF_PROG(lookup_fast_fentry, struct nameidata *nd, struct path *path)
{
	return inc_stats(S_REFS);
}

SEC("kretprobe/d_lookup")
int BPF_KRETPROBE(d_lookup_kretprobe, struct dentry *ret)
{
	inc_stats(S_SLOW);
	if (PT_REGS_RC(ctx) == 0)
		inc_stats(S_MISS);
	return 0;
}

SEC("fexit/d_lookup")
int BPF_PROG(d_lookup_fexit, const struct dentry *parent,
	     const struct qstr *name, struct dentry *ret)
{
	inc_stats(S_SLOW);
	if (ret == NULL)
		inc_stats(S_MISS);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
