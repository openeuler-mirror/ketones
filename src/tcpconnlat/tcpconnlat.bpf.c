// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "tcpconnlat.h"

#include "compat.bpf.h"
#include "maps.bpf.h"

#define AF_INET		2
#define AF_INET6	10

const volatile __u64 target_min_us = 0;
const volatile pid_t target_tgid = 0;

struct piddata {
	char comm[TASK_COMM_LEN];
	u64 ts;
	u32 tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct sock *);
	__type(value, struct piddata);
} start SEC(".maps");

static int trace_connect(struct sock *sock)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct piddata piddata = {};

	if (target_tgid && target_tgid != tgid)
		return 0;

	bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));
	piddata.ts = bpf_ktime_get_ns();
	piddata.tgid = tgid;
	bpf_map_update_elem(&start, &sock, &piddata, BPF_ANY);
	return 0;
}

static int cleanup_sock(struct sock *sock)
{
	bpf_map_delete_elem(&start, &sock);
	return 0;
}

static int handle_tcp_rcv_state_process(void *ctx, struct sock *sk)
{
	struct piddata *piddatap;
	struct event *eventp;
	s64 delta;
	u64 ts;

	if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
		return 0;

	piddatap = bpf_map_lookup_and_delete_elem(&start, &sk);
	if (!piddatap)
		return 0;

	ts = bpf_ktime_get_ns();
	delta = (s64)(ts - piddatap->ts);
	if (delta < 0)
		return 0;

	if (target_min_us && delta / 1000U < target_min_us)
		return 0;

	eventp = reserve_buf(sizeof(*eventp));
	if (!eventp)
		return 0;

	eventp->delta_us = delta / 1000U;
	__builtin_memcpy(&eventp->comm, piddatap->comm,
			 sizeof(eventp->comm));
	eventp->tgid = piddatap->tgid;
	eventp->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	eventp->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	eventp->af = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (eventp->af == AF_INET) {
		eventp->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		eventp->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&eventp->saddr_v6, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&eventp->daddr_v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	submit_buf(ctx, eventp, sizeof(*eventp));
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	return trace_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
	return trace_connect(sk);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock *sk)
{
	return handle_tcp_rcv_state_process(ctx, sk);
}

SEC("kprobe/tcp_v4_destroy_sock")
int BPF_KPROBE(tcp_v4_destroy_sock, struct sock *sk)
{
	return cleanup_sock(sk);
}

SEC("kprobe/tcp_v6_destroy_sock")
int BPF_KPROBE(tcp_v6_destroy_sock, struct sock *sk)
{
	return cleanup_sock(sk);
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk)
{
	return trace_connect(sk);
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(fentry_tcp_v6_connect, struct sock *sk)
{
	return trace_connect(sk);
}

SEC("fentry/tcp_rcv_state_process")
int BPF_PROG(fentry_tcp_rcv_state_process, struct sock *sk)
{
	return handle_tcp_rcv_state_process(ctx, sk);
}

SEC("fentry/tcp_v4_destroy_sock")
int BPF_PROG(fentry_tcp_v4_destroy_sock, struct sock *sk)
{
	return cleanup_sock(sk);
}

SEC("fentry/tcp_v6_destroy_sock")
int BPF_PROG(fentry_tcp_v6_destroy_sock, struct sock *sk)
{
	return cleanup_sock(sk);
}

char LICENSE[] SEC("license") = "GPL";
