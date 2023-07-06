// SPDX-License-Identifier: GPL-2.0
// Copyright @ 2023 - Kylin
// Author: weirongguang <weirongguang@kylinos.cn>
//
// Based on tcpdrop.py - 2018 Brendan Gregg

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tcpdrop.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, unsigned long[PERF_MAX_STACK_DEPTH]);
} stack SEC(".maps");

static __always_inline struct tcphdr *
skb_to_tcphdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)(BPF_CORE_READ(skb, head) +
				 BPF_CORE_READ(skb, transport_header));
}

static __always_inline struct iphdr *
skb_to_iphdr(const struct sk_buff *skb)
{
	return (struct iphdr *)(BPF_CORE_READ(skb, head) +
				BPF_CORE_READ(skb, network_header));
}

static __always_inline __u8
tcp_flag_byte(struct tcphdr *tcp)
{
	union tcp_word_hdr *tp = (union tcp_word_hdr *)(tcp);
	__u32 flags[5];

	bpf_probe_read_kernel(&flags, sizeof(flags), tp->words);
	return (flags[3] >> 8) & 0xFF;
}

static __always_inline void
handle_event(void *ctx, __u16 family, __u8 state,
	     struct tcphdr *tcp, struct iphdr *ip)
{
	struct data_t *data;

	data = reserve_buf(sizeof(*data));
	if (!data)
		return;

	data->af = family;
	data->state = state;
	data->pid = bpf_get_current_pid_tgid() >> 32;
	if (family == AF_INET) {
		BPF_CORE_READ_INTO(&data->saddr_v4, ip, saddr);
		BPF_CORE_READ_INTO(&data->daddr_v4, ip, daddr);
	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&data->saddr_v6, ip, saddr);
		BPF_CORE_READ_INTO(&data->daddr_v6, ip, daddr);
	}
	data->sport = BPF_CORE_READ(tcp, source);
	data->dport = BPF_CORE_READ(tcp, dest);
	data->tcpflags = tcp_flag_byte(tcp);
	data->stack_id = bpf_get_stackid(ctx, &stack, 0);

	submit_buf(ctx, data, sizeof(*data));
}

static __always_inline int
trace_event(void *ctx, struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *tcp = skb_to_tcphdr(skb);
	struct iphdr *ip = skb_to_iphdr(skb);

	if (sk == NULL)
		return 0;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	__u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	handle_event(ctx, family, state, tcp, ip);

	return 0;
}

SEC("kprobe/kfree_skb_reason")
int BPF_KPROBE(kfree_skb_reason_kprobe, struct sk_buff *skb)
{
	return trace_event(ctx, BPF_CORE_READ(skb, sk), skb);
}

SEC("kprobe/tcp_drop")
int BPF_KPROBE(tcp_drop_kprobe, struct sock *sk, struct sk_buff *skb)
{
	return trace_event(ctx, sk, skb);
}

char LICENSE[] SEC("license") = "GPL";
