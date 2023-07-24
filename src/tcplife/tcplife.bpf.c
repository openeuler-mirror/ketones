// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tcplife.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240
#define AF_INET		2
#define AF_INET6	10

const volatile bool filter_sport = false;
const volatile bool filter_dport = false;
const volatile __u16 target_sports[MAX_PORTS] = {};
const volatile __u16 target_dports[MAX_PORTS] = {};
const volatile pid_t target_pid = 0;
const volatile __u16 target_family = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, __u64);
} birth SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, struct ident);
} idents SEC(".maps");

static __always_inline int
inet_sock_set_state_entry(void *ctx, const struct sock *sk,
			  const int oldstate, const int newstate)
{
	bool found;
	pid_t pid;

	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (target_family && family != target_family)
		return 0;

	struct inet_sock *inet_sock = (struct inet_sock *)sk;
	__u16 sport = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));
	if (filter_sport) {
		found = false;
		for (int i = 0; i < MAX_PORTS; i++) {
			if (!target_sports[i])
				return 0;
			if (sport != target_sports[i])
				continue;
			found = true;
			break;
		}
		if (!found)
			return 0;
	}

	__u16 dport = bpf_ntohs(BPF_CORE_READ(inet_sock, sk.__sk_common.skc_dport));
	if (filter_dport) {
		found = false;
		for (int i = 0; i < MAX_PORTS; i++) {
			if (!target_dports[i])
				return 0;
			if (dport != target_dports[i])
				continue;
			found = true;
			break;
		}
		if (!found)
			return 0;
	}

	if (newstate < TCP_FIN_WAIT1) {
		__u64 ts = bpf_ktime_get_ns();
		bpf_map_update_elem(&birth, &sk, &ts, BPF_ANY);
	}

	if (newstate == TCP_SYN_SENT || newstate == TCP_LAST_ACK) {
		pid = bpf_get_current_pid_tgid() >> 32;
		if (target_pid && pid != target_pid)
			return 0;

		struct ident ident = {};
		ident.pid = pid;
		bpf_get_current_comm(ident.comm, sizeof(ident.comm));
		bpf_map_update_elem(&idents, &sk, &ident, BPF_ANY);
	}

	if (newstate != TCP_CLOSE)
		return 0;

	__u64 *start = bpf_map_lookup_and_delete_elem(&birth, &sk);
	if (!start) {
		bpf_map_delete_elem(&idents, &sk);
		return 0;
	}

	__u64 delta_us = (bpf_ktime_get_ns() - *start) / 1000;

	struct ident *identp = bpf_map_lookup_and_delete_elem(&idents, &sk);
	pid = identp ? identp->pid : bpf_get_current_pid_tgid() >> 32;
	if (target_pid && pid != target_pid)
		return 0;

	struct event *event;
	struct tcp_sock *tp = (struct tcp_sock *)sk;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->span_us = delta_us;
	event->rx_b = BPF_CORE_READ(tp, bytes_received);
	event->tx_b = BPF_CORE_READ(tp, bytes_acked);
	event->pid = pid;
	event->sport = sport;
	event->dport = dport;
	event->family = family;
	if (!identp)
		bpf_get_current_comm(&event->comm, sizeof(event->comm));
	else
		bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), identp->comm);
	if (family == AF_INET) {
		BPF_CORE_READ_INTO(&event->saddr, inet_sock, inet_saddr);
		BPF_CORE_READ_INTO(&event->daddr, inet_sock, sk.__sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_v6_rcv_saddr);
		BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_v6_daddr);
	}

	submit_buf(ctx, event, sizeof(*event));

	return 0;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(inet_sock_set_state, const struct sock *sk, const int oldstate,
	     const int newstate)
{
	return inet_sock_set_state_entry(ctx, sk, oldstate, newstate);
}

SEC("raw_tp/inet_sock_set_state")
int BPF_PROG(inet_sock_set_state_raw, const struct sock *sk, const int oldstate,
	     const int newstate)
{
	return inet_sock_set_state_entry(ctx, sk, oldstate, newstate);
}

char LICENSE[] SEC("license") = "GPL";
