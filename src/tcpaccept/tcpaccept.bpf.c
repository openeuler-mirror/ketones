// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: weirongguang <weirongguang@kylinos.cn>
//
// Based on tcpaccept.py - 2015 Brendan Gregg

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tcpaccept.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

#define MAX_PORTS	1024

const volatile pid_t trace_pid = 0;
const volatile bool filter_by_port = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PORTS);
	__type(key, __u16);
	__type(value, __u16);
} ports SEC(".maps");

static __always_inline void
tcp_ip_trace(void *ctx, struct sock *sk, __u32 pid, __u16 lport,
	     __u16 dport, __u16 family)
{
	struct data_t *data;

	data = reserve_buf(sizeof(*data));
	if (!data)
		return;

	if (family == AF_INET) {
		BPF_CORE_READ_INTO(&data->saddr_v4, sk,
				   __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&data->daddr_v4, sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&data->saddr_v6, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&data->daddr_v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	data->af = family;
	data->pid = pid;
	data->lport = lport;
	data->dport = dport;
	bpf_get_current_comm(&data->task, sizeof(data->task));

	submit_buf(ctx, data, sizeof(*data));
}

static __always_inline int
trace_event(void *ctx, struct sock *sk)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u16 family, lport, dport;

	if (trace_pid && trace_pid != pid)
		return 0;

	if (sk == NULL)
		return 0;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

	if (filter_by_port && !bpf_map_lookup_elem(&ports, &lport))
		return 0;

	tcp_ip_trace(ctx, sk, pid, lport, dport, family);

	return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_kretprobe, struct sock *sk)
{
	return trace_event(ctx, sk);
}

char LICENSE[] SEC("license") = "GPL";
