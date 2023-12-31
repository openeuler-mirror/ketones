// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Wenbo Zhang
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "compat.bpf.h"
#include "core_fixes.bpf.h"
#include "maps.bpf.h"
#include "tcppktlat.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;
const volatile pid_t target_tid = 0;
const volatile __u16 target_sport = 0;
const volatile __u16 target_dport = 0;
const volatile __u16 target_family = 0;
const volatile __u64 target_min_us = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
} start SEC(".maps");

static __always_inline int
handle_tcp_probe(struct sock *sk, struct sk_buff *skb)
{
	const struct inet_sock *inet = (struct inet_sock *)sk;
	u64 sock_ident, ts, len, doff;
	const struct tcphdr *th;

	if (target_family && target_family != BPF_CORE_READ(sk, __sk_common.skc_family))
		return 0;
	if (target_sport && target_sport != BPF_CORE_READ(inet, inet_sport))
		return 0;
	if (target_dport && target_dport != BPF_CORE_READ(sk, __sk_common.skc_dport))
		return 0;
	th = (const struct tcphdr *)BPF_CORE_READ(skb, data);
	doff = BPF_CORE_READ_BITFIELD_PROBED(th, doff);
	len = BPF_CORE_READ(skb, len);
	/* `doff * 4` means `__tcp_hdrlen` */
	if (len <= doff * 4)
		return 0;
	sock_ident = get_sock_ident(sk);
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &sock_ident, &ts, BPF_ANY);

	return 0;
}

static __always_inline int
handle_tcp_rcv_space_adjust(void *ctx, struct sock *sk)
{
	const struct inet_sock *inet = (struct inet_sock *)sk;
	u64 sock_ident = get_sock_ident(sk);
	u64 id = bpf_get_current_pid_tgid(), *tsp;
	u32 pid = id >> 32, tid = id;
	struct event *eventp;
	s64 delta_us;
	u16 family;

	tsp = bpf_map_lookup_and_delete_elem(&start, &sock_ident);
	if (!tsp)
		return 0;

	if (target_pid && target_pid != pid)
		return 0;
	if (target_tid && target_tid != tid)
		return 0;

	delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
	if (delta_us < 0 || delta_us <= target_min_us)
		return 0;

	eventp = reserve_buf(sizeof(*eventp));
	if (!eventp)
		return 0;

	eventp->pid = pid;
	eventp->tid = tid;
	eventp->delta_us = delta_us;
	eventp->sport = BPF_CORE_READ(inet, inet_sport);
	eventp->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family == AF_INET) {
		BPF_CORE_READ_INTO(&eventp->saddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&eventp->daddr, sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&eventp->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&eventp->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	eventp->family = family;
	submit_buf(ctx, eventp, sizeof(*eventp));

	return 0;
}

static int handle_tcp_destroy_sock(void *ctx, struct sock *sk)
{
	u64 sock_ident = get_sock_ident(sk);

	bpf_map_delete_elem(&start, &sock_ident);
	return 0;
}

SEC("tp_btf/tcp_probe")
int BPF_PROG(tcp_probe_btf, struct sock *sk, struct sk_buff *skb)
{
	return handle_tcp_probe(sk, skb);
}

SEC("tp_btf/tcp_rcv_space_adjust")
int BPF_PROG(tcp_rcv_space_adjust_btf, struct sock *sk)
{
	return handle_tcp_rcv_space_adjust(ctx, sk);
}

SEC("tp_btf/tcp_destroy_sock")
int BPF_PROG(tcp_destroy_sock_btf, struct sock *sk)
{
	return handle_tcp_destroy_sock(ctx, sk);
}

SEC("raw_tp/tcp_probe")
int BPF_PROG(tcp_probe_raw, struct sock *sk, struct sk_buff *skb)
{
	return handle_tcp_probe(sk, skb);
}

SEC("raw_tp/tcp_rcv_space_adjust")
int BPF_PROG(tcp_rcv_space_adjust_raw, struct sock *sk)
{
	return handle_tcp_rcv_space_adjust(ctx, sk);
}

SEC("raw_tp/tcp_destroy_sock")
int BPF_PROG(tcp_destroy_sock_raw, struct sock *sk)
{
	return handle_tcp_destroy_sock(ctx, sk);
}

char LICENSE[] SEC("license") = "GPL";
