// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __NETFILTER_H
#define __NETFILTER_H

#define MAX_HOOKS		32
#define NF_UNKNOWN		5

/* for kprobes, entry is function IP + sizeof(kprobe_opcode_t),
 * subtract in BPF prog context to get fn address.
 */
#ifdef __TARGET_ARCH_x86
#define NF_IP_FIX(ip)              (ip - sizeof(kprobe_opcode_t))
#else
#define NF_IP_FIX(ip)              ip
#endif

struct hook_function {
	__u8 hooknum;
	__u64 hookfn;
};

struct event_data {
	__u8 result;
	__u8 hooknum;
	__u64 times;
	__u64 hookfn;
};

struct hook_data {
	__u8 result;
	__u16 index;
	__u16 numhookfn;
	__u64 start_times;
};

static char *nf_inet_hooks[] = {
	"NF_INET_PRE_ROUTING",
	"NF_INET_LOCAL_IN",
	"NF_INET_FORWARD",
	"NF_INET_LOCAL_OUT",
	"NF_INET_POST_ROUTING"
};

static char *nf_inet_result[] = {
	"NF_DROP",
	"NF_ACCEPT",
	"NF_STOLEN",
	"NF_QUEUE",
	"NF_REPEAT",
	"NF_UNKNOWN"
};

#endif
