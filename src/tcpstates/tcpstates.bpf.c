// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tcpstates.h"
#include "compat.bpf.h"

#define MAX_ENTRIES	10240
#define AF_INET		2
#define AF_INET6	10

const volatile bool filter_by_sport = false;
const volatile bool filter_by_dport = false;
const volatile short target_family = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u16);
	__type(value, __u16);
} sports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u16);
	__type(value, __u16);
} dports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, __u64);
} timestamps SEC(".maps");

static __always_inline int
handle_set_state(void *ctx, const struct sock *sk,
		 const int oldstate, const int newstate)
{
	__u64 delta_us;

	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (target_family && target_family != family)
		return 0;

	struct inet_sock *inet_sock = (struct inet_sock *)sk;

	__u16 sport = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));
	if (filter_by_sport && !bpf_map_lookup_elem(&sports, &sport))
		return 0;

	__u16 dport = bpf_ntohs(BPF_CORE_READ(inet_sock, sk.__sk_common.skc_dport));
	if (filter_by_dport && !bpf_map_lookup_elem(&dports, &dport))
		return 0;

	__u64 *tsp = bpf_map_lookup_elem(&timestamps, &sk);
	__u64 ts = bpf_ktime_get_ns();

	if (!tsp)
		delta_us = 0;
	else
		delta_us = (ts - *tsp) / 1000;

	struct event *event;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->skaddr = (__u64)sk;
	event->delta_us = delta_us;
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->oldstate = oldstate;
	event->newstate = newstate;
	event->family = family;
	event->sport = sport;
	event->dport = dport;
	bpf_get_current_comm(&event->task, sizeof(event->task));

	if (family == AF_INET) {
		BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	submit_buf(ctx, event, sizeof(*event));

	if (newstate == TCP_CLOSE)
		bpf_map_delete_elem(&timestamps, &sk);
	else
		bpf_map_update_elem(&timestamps, &sk, &ts, BPF_ANY);

	return 0;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(inet_sock_set_state, const struct sock *sk, const int oldstate,
	     const int newstate)
{
	return handle_set_state(ctx, sk, oldstate, newstate);
}

SEC("raw_tp/inet_sock_set_state")
int BPF_PROG(inet_sock_set_state_raw, const struct sock *sk, const int oldstate,
	     const int newstate)
{
	return handle_set_state(ctx, sk, oldstate, newstate);
}

char LICENSE[] SEC("license") = "GPL";
