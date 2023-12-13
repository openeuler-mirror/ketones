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
tcp_ipv4_trace(void *ctx, struct sock *sk, __u32 pid, __u16 lport, __u16 dport)
{
	struct data_t *data4;

	data4 = reserve_buf(sizeof(*data4));
	if (!data4)
		return;

	data4->af = AF_INET;
	data4->pid = pid;
	BPF_CORE_READ_INTO(&data4->saddr_v4, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&data4->daddr_v4, sk, __sk_common.skc_daddr);
	data4->lport = lport;
	data4->dport = dport;
	bpf_get_current_comm(&data4->task, sizeof(data4->task));

	submit_buf(ctx, data4, sizeof(*data4));
}

static __always_inline void
tcp_ipv6_trace(void *ctx, struct sock *sk, __u32 pid, __u16 lport, __u16 dport)
{
	struct data_t *data6;

	data6 = reserve_buf(sizeof(*data6));
	if (!data6)
		return;

	data6->af = AF_INET6;
	data6->pid = pid;
	BPF_CORE_READ_INTO(&data6->saddr_v6, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&data6->daddr_v6, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	data6->lport = lport;
	data6->dport = dport;
	bpf_get_current_comm(&data6->task, sizeof(data6->task));

	submit_buf(ctx, data6, sizeof(*data6));
}

static __always_inline int
trace_event(void *ctx, struct sock *sk)
{
	__u16 *port;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (trace_pid && trace_pid != pid)
		return 0;

	if (sk == NULL)
		return 0;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

	port = bpf_map_lookup_elem(&ports, &lport);
	if (filter_by_port && !port)
		return 0;

	if (family == AF_INET)
		tcp_ipv4_trace(ctx, sk, pid, lport, dport);
	else if (family == AF_INET6)
		tcp_ipv6_trace(ctx, sk, pid, lport, dport);

	return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_kretprobe, struct sock *sk)
{
	return trace_event(ctx, sk);
}

char LICENSE[] SEC("license") = "GPL";
