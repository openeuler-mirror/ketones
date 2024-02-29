// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Author: Jackie Liu <liuyun01@kylinos.cn>
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"
#include "netqtop.h"

/* Array of length 1 for device name */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, union name_buf);
} name_map SEC(".maps");

/* Table for transmit & receive packets */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_QUEUE_NUM);
	__type(key, u16);
	__type(value, struct queue_data);
} tx_q SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_QUEUE_NUM);
	__type(key, u16);
	__type(value, struct queue_data);
} rx_q SEC(".maps");

static bool name_filter(struct sk_buff *skb)
{
	/* get device name from skb */
	union name_buf real_devname;
	struct net_device *dev;
	int key = 0;
	union name_buf *leaf;

	bpf_probe_read(&dev, sizeof(skb->dev), ((char *)skb + offsetof(struct sk_buff, dev)));
	bpf_probe_read(&real_devname, IFNAMSIZ, dev->name);

	leaf = bpf_map_lookup_elem(&name_map, &key);
	if (!leaf)
		return false;

	if ((leaf->name_int).hi != real_devname.name_int.hi ||
	    (leaf->name_int).lo != real_devname.name_int.lo)
		return false;

	return true;
}

static void update_data(struct queue_data *data, __u64 len)
{
	data->total_pkt_len += len;
	data->num_pkt++;

	if (len / 64 == 0)
		data->size_64B++;
	else if (len / 512 == 0)
		data->size_512B++;
	else if (len / 2048 == 0)
		data->size_2K++;
	else if (len / 16384 == 0)
		data->size_16K++;
	else if (len / 65536 == 0)
		data->size_64K++;
}

SEC("raw_tp/net_dev_start_xmit")
int BPF_PROG(tracepoint_net_dev_start_xmit, struct sk_buff *skb)
{
	u16 qid = BPF_CORE_READ(skb, queue_mapping);
	struct queue_data newdata, *data;

	if (!name_filter(skb))
		return 0;

	__builtin_memset(&newdata, 0, sizeof(newdata));
	data = bpf_map_lookup_or_try_init(&tx_q, &qid, &newdata);
	if (!data)
		return 0;

	update_data(data, BPF_CORE_READ(skb, len));
	return 0;
}

static inline bool skb_rx_queue_recorded(const struct sk_buff *skb)
{
	return BPF_CORE_READ(skb, queue_mapping) != 0;
}

static inline u16 skb_get_rx_queue(const struct sk_buff *skb)
{
	return BPF_CORE_READ(skb, queue_mapping) - 1;
}

SEC("raw_tp/netif_receive_skb")
int BPF_PROG(tracepoint_netif_receive_skb, struct sk_buff *skb)
{
	/* case 1: if the NIC does not support multi-queue feature, there is only
	 *         one queue (qid is always 0).
	 * case 2: if the NIC supports mult-queue feature, there are several queues
	 *         with different qid (from 0 to n-1).
	 * The net device driver should mark queue id by API 'skb_record_rx_queue'
	 * for a recieved skb, otherwise it should be a BUG (all of the packets are
	 * reported as queue 0). For example, virtio net driver is fixed for Linux:
	 * commit: 133bbb18ab1a2("virtio-net: per-queue RPS config")
	 */
	u16 qid = 0;
	struct queue_data newdata, *data;

	if (!name_filter(skb))
		return 0;

	if (skb_rx_queue_recorded(skb))
		qid = skb_get_rx_queue(skb);

	__builtin_memset(&newdata, 0, sizeof(newdata));
	data = bpf_map_lookup_or_try_init(&rx_q, &qid, &newdata);
	if (!data)
		return 0;

	update_data(data, BPF_CORE_READ(skb, len));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
