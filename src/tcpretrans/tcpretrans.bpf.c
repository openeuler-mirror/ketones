// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: weirongguang <weirongguang@kylinos.cn>
//
// Based on tcpretrans.py - Brendan Gregg and Matthias Tafelmeier

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tcpretrans.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

const volatile bool do_count = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv4_flow_key_t);
	__type(value, u64);
} ipv4_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv6_flow_key_t);
	__type(value, u64);
} ipv6_count SEC(".maps");

static __always_inline void
tcp_ipv4_count(struct sock *sk, __u16 lport, __u16 dport)
{
	struct ipv4_flow_key_t flow_key = {};
	static __u64 zero;
	__u64 *val;

	BPF_CORE_READ_INTO(&flow_key.saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&flow_key.daddr, sk, __sk_common.skc_daddr);
	flow_key.lport = lport;
	flow_key.dport = dport;
	val = bpf_map_lookup_or_try_init(&ipv4_count, &flow_key, &zero);
	if (!val)
		return;
	__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static __always_inline void
tcp_ipv4_trace(void *ctx, struct sock *sk, __u32 pid, __u16 lport,
	       __u16 dport, __u8 state, __u64 type)
{
	struct event *data4;

	data4 = reserve_buf(sizeof(*data4));
	if (!data4)
		return;

	data4->af = AF_INET;
	data4->pid = pid;
	data4->type = type;
	BPF_CORE_READ_INTO(&data4->saddr_v4, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&data4->daddr_v4, sk, __sk_common.skc_daddr);
	data4->lport = lport;
	data4->dport = dport;
	data4->state = state;

	submit_buf(ctx, data4, sizeof(*data4));
}

static __always_inline void
tcp_ipv6_count(struct sock *sk, __u16 lport, __u16 dport)
{
	struct ipv6_flow_key_t flow_key = {};
	static const __u64 zero;
	__u64 *val;

	BPF_CORE_READ_INTO(&flow_key.saddr, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&flow_key.daddr, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	flow_key.lport = lport;
	flow_key.dport = dport;

	val = bpf_map_lookup_or_try_init(&ipv6_count, &flow_key, &zero);
	if (!val)
		return;
	__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static __always_inline void
tcp_ipv6_trace(void *ctx, struct sock *sk, __u32 pid, __u16 lport,
	       __u16 dport, __u8 state, __u64 type)
{
	struct event *data6;

	data6 = reserve_buf(sizeof(*data6));
	if (!data6)
		return;

	data6->af = AF_INET6;
	data6->pid = pid;
	data6->lport = lport;
	data6->dport = dport;
	data6->type = type;
	data6->state = state;
	BPF_CORE_READ_INTO(&data6->saddr_v6, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&data6->daddr_v6, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);

	submit_buf(ctx, data6, sizeof(*data6));
}

static __always_inline int
trace_event(void *ctx, struct sock *sk, __u64 type)
{
	if (sk == NULL)
		return 0;

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	__u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);

	if (family == AF_INET) {
		if (do_count)
			tcp_ipv4_count(sk, lport, dport);
		else
			tcp_ipv4_trace(ctx, sk, pid, lport, dport, state, type);
	} else if (family == AF_INET6) {
		if (do_count)
			tcp_ipv6_count(sk, lport, dport);
		else
			tcp_ipv6_trace(ctx, sk, pid, lport, dport, state, type);
	}

	return 0;
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int tcp_retransmit_skb_entry(struct trace_event_raw_sys_enter *ctx)
{
	return trace_event(ctx, (struct sock *)ctx->args[0], RETRANSMIT);
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(tcp_retransmit_skb_kprobe, struct sock *sk)
{
	return trace_event(ctx, sk, RETRANSMIT);
}

SEC("kprobe/tcp_send_loss_probe")
int BPF_KPROBE(tcp_send_loss_probe_kprobe, struct sock *sk)
{
	return trace_event(ctx, sk, TLP);
}

char LICENSE[] SEC("license") = "GPL";
