// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "maps.bpf.h"
#include "tcplinks.h"

#define AF_INET		2
#define AF_INET6	10

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, struct link);
} links SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, __u32);
} idents SEC(".maps");

static int init_new_connection(struct sock *sk, pid_t pid)
{
	struct link link = {};
	struct inet_sock *inet_sock = (struct inet_sock *)sk;

	link.sport = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));
	link.dport = bpf_ntohs(BPF_CORE_READ(inet_sock, sk.__sk_common.skc_dport));
	link.pid = pid ?: bpf_get_current_pid_tgid() >> 32;
	link.family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (link.family == AF_INET) {
		BPF_CORE_READ_INTO(&link.saddr, inet_sock, inet_saddr);
		BPF_CORE_READ_INTO(&link.daddr, inet_sock, sk.__sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&link.saddr, sk, __sk_common.skc_v6_rcv_saddr);
		BPF_CORE_READ_INTO(&link.daddr, sk, __sk_common.skc_v6_daddr);
	}

	bpf_map_update_elem(&links, &sk, &link, BPF_NOEXIST);
	return 0;
}

static int inet_sock_set_state_entry(struct sock *sk, const int newstate)
{
	if (!sk)
		return 0;

	if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != IPPROTO_TCP)
		return 0;

	struct link *linkp = bpf_map_lookup_elem(&links, &sk);

	if (newstate >= TCP_FIN_WAIT1) {
		if (linkp) {
			bpf_map_delete_elem(&links, &sk);
			bpf_map_delete_elem(&idents, &sk);
		}
		return 0;
	}

	/* Found link, return direct */
	if (linkp)
		return 0;

	if (newstate == TCP_SYN_SENT) {
		pid_t __pid = bpf_get_current_pid_tgid() >> 32;
		bpf_map_update_elem(&idents, &sk, &__pid, BPF_ANY);
	}

	if (newstate != TCP_ESTABLISHED)
		return 0;

	/* record */
	pid_t *pidp = bpf_map_lookup_and_delete_elem(&idents, &sk);
	return init_new_connection(sk, pidp ? *pidp : 0);
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(inet_sock_set_state, struct sock *sk, const int oldstate,
	     const int newstate)
{
	return inet_sock_set_state_entry(sk, newstate);
}

SEC("raw_tp/inet_sock_set_state")
int BPF_PROG(inet_sock_set_state_raw, struct sock *sk, const int oldstate,
	     const int newstate)
{
	return inet_sock_set_state_entry(sk, newstate);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct link *link = bpf_map_lookup_elem(&links, &sk);
	int ret = 0;

	if (link)
		link->sent += size;
	else
		ret = init_new_connection(sk, 0);

	return ret;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	int ret = 0;

	if (copied <= 0)
		return 0;

	struct link *link = bpf_map_lookup_elem(&links, &sk);
	if (link)
		link->received += copied;
	else
		ret = init_new_connection(sk, 0);

	return ret;
}

char LICENSE[] SEC("license") = "GPL";
