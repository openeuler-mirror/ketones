// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Rongguang Wei <weirongguang@kylinos.cn>
//
// Based on tcpsubnet.py - 2017 Rodrigo Manyari

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "tcpsubnet.h"
#include "maps.bpf.h"

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define MAXENTRIES	1024

const volatile struct subnet subnets[MAX_NETS] = {};
const volatile __u16 subnet_len = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAXENTRIES);
	__type(key, __u16);
	__type(value, __u64);
} ipv4_send_bytes SEC(".maps");

static __always_inline void
handler_event(__u32 dst, size_t size)
{
	static const __u64 zero;
	__u16 index_key;
	__u64 *val;

	for (int i = 0; i < subnet_len; i++) {
		if ((dst & subnets[i].netmask) ==
		    (subnets[i].netaddr & subnets[i].netmask)) {
			index_key = i,
			val = bpf_map_lookup_or_try_init(&ipv4_send_bytes,
							 &index_key, &zero);
			if (val)
				__atomic_add_fetch(val, size, __ATOMIC_RELAXED);
			break;
		}
	}
}

static __always_inline int
trace_event(void *ctx, struct sock *sk, size_t size)
{
	if (AF_INET == BPF_CORE_READ(sk, __sk_common.skc_family))
		handler_event(BPF_CORE_READ(sk, __sk_common.skc_daddr), size);

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg_kprobe, struct sock *sk, struct msghdr *msg,
	       size_t size)
{
	return trace_event(ctx, sk, size);
}

char LICENSE[] SEC("license") = "GPL";
