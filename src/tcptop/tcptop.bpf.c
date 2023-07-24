// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tcptop.h"
#include "maps.bpf.h"

/* Taken from kernel include/linux/socket.h */
#define AF_INET		2	/* Internet IP protocol */
#define AF_INET6	10	/* IP version 6 */

const volatile bool filter_cg = false;
const volatile pid_t target_pid = -1;
const volatile int target_family = -1;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_key_t);
	__type(value, struct traffic_t);
} ip_map SEC(".maps");

static __always_inline int
probe_ip(bool receiving, struct sock *sk, size_t size)
{
	struct ip_key_t ip_key = {};
	struct traffic_t *trafficp, zero = {};
	u16 family;
	u32 pid;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (target_pid != -1 && target_pid != pid)
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (target_family != -1 && target_family != family)
		return 0;

	/* drop */
	if (family != AF_INET && family != AF_INET6)
		return 0;

	ip_key.pid = pid;
	bpf_get_current_comm(&ip_key.name, sizeof(ip_key.name));
	ip_key.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	ip_key.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	ip_key.family = family;

	if (family == AF_INET) {
		bpf_core_read(&ip_key.saddr,
			      sizeof(sk->__sk_common.skc_rcv_saddr),
			      &sk->__sk_common.skc_rcv_saddr);
		bpf_core_read(&ip_key.daddr,
			      sizeof(sk->__sk_common.skc_daddr),
			      &sk->__sk_common.skc_daddr);
	} else {
		/*
		 * family == AF_INET6
		 * we already checked above family is correct.
		 */
		bpf_core_read(&ip_key.saddr,
			      sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
			      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_core_read(&ip_key.daddr,
			      sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
			      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	trafficp = bpf_map_lookup_or_try_init(&ip_map, &ip_key, &zero);
	if (!trafficp)
		return 0;

	if (receiving)
		trafficp->received += size;
	else
		trafficp->sent += size;

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	return probe_ip(false, sk, size);
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are avaiable.
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;

	return probe_ip(true, sk, copied);
}

char LICENSE[] SEC("license") = "GPL";
