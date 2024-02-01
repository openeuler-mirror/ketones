// SPDX-License-Identifier: GPL-2.0
/* dddos          DDOS detection system.
 *
 * Written as a basic tracing example of using ePBF
 * to detect a potential DDOS attack against a system.
 *
 * Copyright (c) 2019 Jugurtha BELKALEM.
 * Copyright (c) 2024 Jackie Liu <liuyun01@kylinos.cn>
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "compat.bpf.h"

#include "dddos.h"

#define MAX_NB_PACKETS 1000
#define LEGAL_DIFF_TIMESTAMP_PACKETS 1000000

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 2); /* index 0 for packets number, index 1 for timestamp */
	__type(key, __u64);
	__type(value, __u64);
} rcv_packets SEC(".maps");

static int detect_ddos(struct pt_regs *ctx, void *skb)
{
	/* Used to count number of received packets */
	__u64 rcv_packets_nb_index = 0, rcv_packets_nb_inter = 1, *rcv_packets_nb_ptr;
	/* Used to measure elapsed time between 2 successive received packets */
	__u64 rcv_packets_ts_index = 1, rcv_packets_ts_inter = 0, *rcv_packets_ts_ptr;

	/* The algorithm analyses packets received by ip_rcv function
	 * and measures the difference in reception time between each packet.
	 * DDOS flooders send millions of packets such that difference of
	 * timestamp between 2 successive packets is so small
	 * (which is not like regular applications behaviour).
	 * This script looks for this difference in time and if it sees
	 * more than MAX_NB_PACKETS successive packets with a difference
	 * of timestamp between each one of them less than
	 * LEGAL_DIFF_TIMESTAMP_PACKETS ns,
	 * ------------------ It Triggers an ALERT --------------
	 * Those setting must be adapted depending on regular network traffic
	 * ------------------------------------------------------------------
	 * Important: this is a rudimentary intrusion detection system, one can
	 * test a real case attack using hping3. However; if regular network
	 * traffice increases above predefined detection settings, a false
	 * positive alert will be triggered (an example would be the
	 * case of large file downloads).
	 */
	rcv_packets_nb_ptr = bpf_map_lookup_elem(&rcv_packets, &rcv_packets_nb_index);
	rcv_packets_ts_ptr = bpf_map_lookup_elem(&rcv_packets, &rcv_packets_ts_index);

	if (rcv_packets_nb_ptr && rcv_packets_ts_ptr) {
		rcv_packets_nb_inter = *rcv_packets_nb_ptr;
		rcv_packets_ts_inter = bpf_ktime_get_ns() - *rcv_packets_ts_ptr;

		if (rcv_packets_ts_inter < LEGAL_DIFF_TIMESTAMP_PACKETS)
			rcv_packets_nb_inter++;
		else
			rcv_packets_nb_inter = 0;

		if (rcv_packets_nb_inter > MAX_NB_PACKETS) {
			struct event *e;

			e = reserve_buf(sizeof(struct event));
			if (!e)
				return 0;

			e->nb_ddos_packets = rcv_packets_nb_inter;
			submit_buf(ctx, e, sizeof(*e));
		}
	}

	rcv_packets_ts_inter = bpf_ktime_get_ns();
	bpf_map_update_elem(&rcv_packets, &rcv_packets_nb_index, &rcv_packets_nb_inter, BPF_ANY);
	bpf_map_update_elem(&rcv_packets, &rcv_packets_ts_index, &rcv_packets_ts_inter, BPF_ANY);

	return 0;
}

SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv_kprobe, struct sk_buff *skb)
{
	return detect_ddos(ctx, skb);
}

char LICENSE[] SEC("license") = "GPL";
