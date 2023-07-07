// SPDX-License-Identifier: GPL-2.0
// Copyright @ 2023 - Kylin
// Author: weirongguang <weirongguang@kylinos.cn>

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tcprst.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

/* Define here, because there are conflicts with include files */
#define AF_INET		2

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

static __always_inline void
handle_no_sock(struct sk_buff *skb, struct data_t *data)
{
	struct tcphdr *tcp = skb_to_tcphdr(skb);
	struct iphdr *ip = skb_to_iphdr(skb);

	if (BPF_CORE_READ(ip, protocol) != IPPROTO_TCP)
		return;

	/* No sock and the skc_state is not exist */
	data->state = 0;
	BPF_CORE_READ_INTO(&data->saddr_v4, ip, saddr);
	BPF_CORE_READ_INTO(&data->daddr_v4, ip, daddr);
	BPF_CORE_READ_INTO(&data->sport, tcp, source);
	BPF_CORE_READ_INTO(&data->dport, tcp, dest);
}

static __always_inline void
handle_sock(struct sock *sk, struct data_t *data)
{
	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return;

	if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET)
		return;

	BPF_CORE_READ_INTO(&data->state, sk, __sk_common.skc_state);
	BPF_CORE_READ_INTO(&data->saddr_v4, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&data->daddr_v4, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&data->sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&data->dport, sk, __sk_common.skc_dport);
}

static __always_inline int
trace_event(void *ctx, struct sock *sk, struct sk_buff *skb, __u8 direct)
{
	struct data_t *data;

	data = reserve_buf(sizeof(*data));
	if (!data)
		return 0;

	data->direct = direct;
	data->pid = bpf_get_current_pid_tgid() >> 32;
	data->stack_id = bpf_get_stackid(ctx, &stack, 0);

	if (sk)
		handle_sock(sk, data);
	else if (skb)
		handle_no_sock(skb, data);

	submit_buf(ctx, data, sizeof(*data));

	return 0;
}

SEC("kprobe/tcp_send_active_reset")
int BPF_KPROBE(tcp_send_active_reset_kprobe, struct sock *sk)
{
	return trace_event(ctx, sk, NULL, 1);
}

SEC("kprobe/tcp_v4_send_reset")
int BPF_KPROBE(tcp_v4_send_reset_kprobe, struct sock *sk, struct sk_buff *skb)
{
	return trace_event(ctx, sk, skb, 1);
}

SEC("kprobe/tcp_reset")
int BPF_KPROBE(tcp_reset_kprobe, struct sock *sk)
{
	return trace_event(ctx, sk, NULL, 0);
}

char LICENSE[] SEC("license") = "GPL";
