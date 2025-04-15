// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on tcpcong.py - Ping Gan

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "tcpcong.h"
#include "maps.bpf.h"
#include "bits.bpf.h"

#define MAX_ENTRIES	8192
#define AF_INET		2
#define AF_INET6	10

const volatile bool dist = false;
const volatile bool microseconds = false;
const volatile __u16 start_lport = 1;
const volatile __u16 end_lport = 0;
const volatile __u16 start_rport = 1;
const volatile __u16 end_rport = 0;
static struct hist zero = {0};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, ip_flow_key_t);
	__type(value, data_val_t);
} ipv4_stat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, ip_flow_key_t);
	__type(value, data_val_t);
} ipv6_stat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 5);
	__type(key, __u16);
	__type(value, struct hist);
} hists SEC(".maps");

typedef struct process_key {
	char comm[TASK_COMM_LEN];
	u32  tid;
} process_key_t;

typedef struct ipv4_flow_val {
	ip_flow_key_t ip_key;
	u16  cong_state;
} ip_flow_val_t;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, process_key_t);
	__type(value, ip_flow_val_t);
} start_ip SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, process_key_t);
	__type(value, struct sock *);
} sock_store SEC(".maps");

static inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
	return (struct inet_connection_sock *)sk;
}

static int data_stat(data_val_t *datap, u8 new_cong_state, u16 last_cong_state)
{
	struct hist *histp;
	u64 slot;
	u64 ts, ts1;

	ts1 = bpf_ktime_get_ns();
	ts = ts1 - datap->last_ts;
	datap->last_ts = ts1;
	datap->last_cong_stat = new_cong_state;
	ts /= 1000;

	if (dist) {
		histp = bpf_map_lookup_or_try_init(&hists, &last_cong_state, &zero);
		if (!histp)
			return 0;
		if (!microseconds)
			ts /= 1000;
		slot = log2l(ts);
		if (slot >= MAX_SLOTS)
			slot = MAX_SLOTS - 1;
		__sync_fetch_and_add(&histp->slots[slot], 1);
	} else {
		datap->total_changes += 1;
		if (last_cong_state == (TCP_CA_Open + 1))
			datap->open_dura += ts;
		else if (last_cong_state == (TCP_CA_Disorder + 1))
			datap->disorder_dura += ts;
		else if (last_cong_state == (TCP_CA_CWR + 1))
			datap->cwr_dura += ts;
		else if (last_cong_state == (TCP_CA_Recovery + 1))
			datap->recover_dura += ts;
		else if (last_cong_state == (TCP_CA_Loss + 1))
			datap->loss_dura += ts;
	}

	return 0;
}

static int entry_func(struct sock *sk)
{
	process_key_t key = {0};
	u64 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	struct inet_connection_sock *icsk = inet_csk(sk);
	u8 cong_status;
	ip_flow_val_t ip_val = {0};

	cong_status = BPF_CORE_READ_BITFIELD_PROBED(icsk, icsk_ca_state);
	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	key.tid = bpf_get_current_pid_tgid();

	ip_val.ip_key.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	ip_val.ip_key.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	ip_val.cong_state = cong_status + 1;

	if (start_lport <= end_lport &&
	    !(ip_val.ip_key.lport >= start_lport && ip_val.ip_key.lport <= end_lport))
		return 0;
	if (start_rport <= end_rport &&
	    !(ip_val.ip_key.dport >= start_rport && ip_val.ip_key.dport <= end_rport))
		return 0;

	if (family == AF_INET) {
		ip_val.ip_key.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		ip_val.ip_key.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&ip_val.ip_key.saddr_v6, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&ip_val.ip_key.daddr_v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	bpf_map_update_elem(&start_ip, &key, &ip_val, BPF_ANY);
	bpf_map_update_elem(&sock_store, &key, &sk, BPF_ANY);
	return 0;
}

static int ret_state_update_func(struct sock *sk)
{
	u16 family, last_cong_state;
	process_key_t key = {0};
	struct inet_connection_sock *icsk = inet_csk(sk);
	u8 cong_status;
	data_val_t *datap, data = {0};
	ip_flow_val_t *val;

	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	key.tid = bpf_get_current_pid_tgid();
	cong_status = BPF_CORE_READ_BITFIELD_PROBED(icsk, icsk_ca_state);
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

	val = bpf_map_lookup_and_delete_elem(&start_ip, &key);
	if (!val)
		return 0; // missed

	ip_flow_key_t ip_key = val->ip_key;

	if (family == AF_INET)
		datap = bpf_map_lookup_elem(&ipv4_stat, &ip_key);
	else if (family == AF_INET6)
		datap = bpf_map_lookup_elem(&ipv6_stat, &ip_key);

	if (!datap) {
		data.last_ts = bpf_ktime_get_ns();
		data.last_cong_stat = val->cong_state;
		if (family == AF_INET)
			bpf_map_update_elem(&ipv4_stat, &ip_key, &data, BPF_ANY);
		else if (family == AF_INET6)
			bpf_map_update_elem(&ipv6_stat, &ip_key, &data, BPF_ANY);
	} else {
		last_cong_state = val->cong_state;
		if ((cong_status + 1) != last_cong_state)
			data_stat(datap, cong_status + 1, last_cong_state);
	}

	return 0;
}

static int ret_func(void)
{
	process_key_t key = {0};
	struct sock **sockpp;

	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	key.tid = bpf_get_current_pid_tgid();
	sockpp = bpf_map_lookup_and_delete_elem(&sock_store, &key);
	if (!sockpp)
		return 0; // miss the entry

	return ret_state_update_func(*sockpp);
}

SEC("kprobe/tcp_fastretrans_alert")
int BPF_KPROBE(tcp_fastretrans_alert_kprobe, struct sock *sk)
{
	return entry_func(sk);
}

SEC("kretprobe/tcp_fastretrans_alert")
int BPF_KRETPROBE(tcp_fastretrans_alert_kretprobe)
{
	return ret_func();
}

SEC("fentry/tcp_fastretrans_alert")
int BPF_PROG(tcp_fastretrans_alert_fentry, struct sock *sk)
{
	return entry_func(sk);
}

SEC("fexit/tcp_fastretrans_alert")
int BPF_PROG(tcp_fastretrans_alert_fexit)
{
	return ret_func();
}

SEC("kprobe/tcp_enter_cwr")
int BPF_KPROBE(tcp_enter_cwr_kprobe, struct sock *sk)
{
	return entry_func(sk);
}

SEC("kretprobe/tcp_enter_cwr")
int BPF_KRETPROBE(tcp_enter_cwr_kretprobe)
{
	return ret_func();
}

SEC("fentry/tcp_enter_cwr")
int BPF_PROG(tcp_enter_cwr_fentry, struct sock *sk)
{
	return entry_func(sk);
}

SEC("fexit/tcp_enter_cwr")
int BPF_PROG(tcp_enter_cwr_fexit)
{
	return ret_func();
}

SEC("kprobe/tcp_process_tlp_ack")
int BPF_KPROBE(tcp_process_tlp_ack_kprobe, struct sock *sk)
{
	return entry_func(sk);
}

SEC("kretprobe/tcp_process_tlp_ack")
int BPF_KRETPROBE(tcp_process_tlp_ack_kretprobe)
{
	return ret_func();
}

SEC("fentry/tcp_process_tlp_ack")
int BPF_PROG(tcp_process_tlp_ack_fentry, struct sock *sk)
{
	return entry_func(sk);
}

SEC("fexit/tcp_process_tlp_ack")
int BPF_PROG(tcp_process_tlp_ack_fexit)
{
	return ret_func();
}

SEC("kprobe/tcp_enter_loss")
int BPF_KPROBE(tcp_enter_loss_kprobe, struct sock *sk)
{
	return entry_func(sk);
}

SEC("kretprobe/tcp_enter_loss")
int BPF_KRETPROBE(tcp_enter_loss_kretprobe)
{
	return ret_func();
}

SEC("fentry/tcp_enter_loss")
int BPF_PROG(tcp_enter_loss_fentry, struct sock *sk)
{
	return entry_func(sk);
}

SEC("fexit/tcp_enter_loss")
int BPF_PROG(tcp_enter_loss_fexit)
{
	return ret_func();
}

SEC("kprobe/tcp_enter_recovery")
int BPF_KPROBE(tcp_enter_recovery_kprobe, struct sock *sk)
{
	return entry_func(sk);
}

SEC("kretprobe/tcp_enter_recovery")
int BPF_KRETPROBE(tcp_enter_recovery_kretprobe)
{
	return ret_func();
}

SEC("fentry/tcp_enter_recovery")
int BPF_PROG(tcp_enter_recovery_fentry, struct sock *sk)
{
	return entry_func(sk);
}

SEC("fexit/tcp_enter_recovery")
int BPF_PROG(tcp_enter_recovery_fexit)
{
	return ret_func();
}

SEC("tracepoint/tcp/tcp_cong_state_set")
int handle_tcp_cong(struct trace_event_raw_tcp_cong_state_set *ctx)
{
	u16 family, last_cong_state;
	u8 cong_state;
	const struct sock *sk = (const struct sock *)ctx->skaddr;
	data_val_t *datap, data = {0};
	ip_flow_key_t key = {0};

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	cong_state = ctx->cong_state;

	key.lport = ctx->sport;
	key.dport = ctx->dport;

	if (start_lport <= end_lport && !(key.lport >= start_lport && key.lport <= end_lport))
		return 0;
	if (start_rport <= end_rport && !(key.dport >= start_rport && key.dport <= end_rport))
		return 0;

	if (family == AF_INET) {
		key.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		key.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		datap = bpf_map_lookup_elem(&ipv4_stat, &key);
	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&key.saddr_v6, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&key.daddr_v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		datap = bpf_map_lookup_elem(&ipv6_stat, &key);
	}

	if (!datap) {
		data.last_ts = bpf_ktime_get_ns();
		data.last_cong_stat = cong_state + 1;
		if (family == AF_INET)
			bpf_map_update_elem(&ipv4_stat, &key, &data, BPF_ANY);
		else if (family == AF_INET6)
			bpf_map_update_elem(&ipv6_stat, &key, &data, BPF_ANY);
	} else {
		last_cong_state = datap->last_cong_stat;
		if ((cong_state + 1) != last_cong_state)
			data_stat(datap, cong_state + 1, last_cong_state);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
