// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "tcprtt.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

const volatile bool target_laddr_hist = false;
const volatile bool target_raddr_hist = false;
const volatile bool target_show_ext = false;
const volatile __u16 target_sport = 0;
const volatile __u16 target_dport = 0;
const volatile __u32 target_saddr = 0;
const volatile __u32 target_daddr = 0;
const volatile bool target_ms = false;

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist zero;

static __always_inline int
handle_tcp_rcv_established(struct sock *sk)
{
	const struct inet_sock *inet = (struct inet_sock *)sk;
	struct tcp_sock *ts = (struct tcp_sock *)sk;
	struct hist *histp;
	u64 key, slot;
	u32 srtt;

	if (target_sport && target_sport != BPF_CORE_READ(inet, inet_sport))
		return 0;
	if (target_dport && target_dport != BPF_CORE_READ(sk, __sk_common.skc_dport))
		return 0;
	if (target_saddr && target_saddr != BPF_CORE_READ(inet, inet_saddr))
		return 0;
	if (target_daddr && target_daddr != BPF_CORE_READ(sk, __sk_common.skc_daddr))
		return 0;

	if (target_laddr_hist)
		key = BPF_CORE_READ(inet, inet_saddr);
	else if (target_raddr_hist)
		key = BPF_CORE_READ(inet, sk.__sk_common.skc_daddr);
	else
		key = 0;

	histp = bpf_map_lookup_or_try_init(&hists, &key, &zero);
	if (!histp)
		return 0;

	srtt = BPF_CORE_READ(ts, srtt_us) >> 3;
	if (target_ms)
		srtt /= 1000U;
	slot = log2l(srtt);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
	if (target_show_ext){
		__sync_fetch_and_add(&histp->latency, srtt);
		__sync_fetch_and_add(&histp->cnt, 1);
	}
	return 0;
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
	return handle_tcp_rcv_established(sk);
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_kprobe, struct sock *sk)
{
	return handle_tcp_rcv_established(sk);
}

char LICENSE[] SEC("license") = "GPL";
