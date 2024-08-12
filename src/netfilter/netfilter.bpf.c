// SPDX-License-Identifier: GPL-2.0
// Copyright @ 2023 - Kylin
// Author: Rongguang Wei <weirongguang@kylinos.cn>

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "netfilter.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

static int zero = 0;

// Array of length 1 for current hook num
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, __u8);
} current_hook_num SEC(".maps");

// Array of length 1 for current hook function
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, __u64);
} current_hook_func SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_HOOKS);
	__type(key, struct hook_function);
	__type(value, struct hook_data);
} hooks_data SEC(".maps");

static __always_inline int
get_current_hook_func_and_num(struct hook_function *hook_func, bool delete)
{
	__u64 *hookfn;
	__u8 *hooknum;

	if (delete) {
		hookfn = bpf_map_lookup_and_delete_elem(&current_hook_func, &zero);
		hooknum = bpf_map_lookup_and_delete_elem(&current_hook_num, &zero);
	} else {
		hookfn = bpf_map_lookup_elem(&current_hook_func, &zero);
		hooknum = bpf_map_lookup_elem(&current_hook_num, &zero);
	}

	if (!hookfn || !hooknum)
		return -1;

	hook_func->hooknum = *hooknum;
	hook_func->hookfn = *hookfn;

	return 0;
}

static __always_inline int enter_hook(struct pt_regs *ctx)
{
	__u64 hook_ip = NF_IP_FIX(PT_REGS_IP_CORE(ctx));

	bpf_map_update_elem(&current_hook_func, &zero, &hook_ip, BPF_ANY);

	return 0;
}

static __always_inline int exit_hook(unsigned int verdict)
{
	struct hook_data *hook_data;
	struct hook_function hook_func = {};

	if (get_current_hook_func_and_num(&hook_func, false))
		return 0;

	hook_data = bpf_map_lookup_elem(&hooks_data, &hook_func);
	if (!hook_data)
		return 0;

	hook_data->result = verdict;
	bpf_map_update_elem(&hooks_data, &hook_func, hook_data, BPF_ANY);

	return 0;
}

static __always_inline int enter_nf_hook_slow(struct nf_hook_state *state,
					      const struct nf_hook_entries *e)
{
	struct hook_data hook_data = {};
	struct hook_function hook_func = {};
	__u16 num_hook_entries = BPF_CORE_READ(e, num_hook_entries);
	__u8 hooknum = BPF_CORE_READ(state, hook);
	const void *hook;
	int i;

	hook_func.hooknum = hooknum;
	hook_data.numhookfn = num_hook_entries;
	bpf_map_update_elem(&current_hook_num, &zero, &hooknum, BPF_ANY);
	for (i = 0; i < MAX_HOOKS; i++) {
		if (i == num_hook_entries)
			break;
		BPF_CORE_READ_INTO(&hook, e, hooks[i]);
		hook_func.hookfn = (__u64)hook;
		hook_data.index = i;
		hook_data.start_times = bpf_ktime_get_ns();
		bpf_map_update_elem(&hooks_data, &hook_func, &hook_data, BPF_ANY);
	}

	return 0;
}

static __always_inline int exit_nf_hook_slow(void *ctx, int result)
{
	struct hook_function hook_func = {};
	struct event_data *event;
	struct hook_data *hook_data;

	if (get_current_hook_func_and_num(&hook_func, true))
		return 0;

	hook_data = bpf_map_lookup_elem(&hooks_data, &hook_func);
	if (!hook_data)
		return 0;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->result = result;
	event->hooknum = hook_func.hooknum;
	event->hookfn = hook_func.hookfn;
	event->times = (bpf_ktime_get_ns() - hook_data->start_times) / 1000;

	submit_buf(ctx, event, sizeof(*event));

	return 0;
}

SEC("fentry/nf_hook_slow")
int BPF_PROG(nf_hook_slow, struct sk_buff *skb, struct nf_hook_state *state,
	     const struct nf_hook_entries *e)
{
	return enter_nf_hook_slow(state, e);
}

SEC("kprobe/nf_hook_slow")
int BPF_KPROBE(nf_hook_slow_kprobe, struct sk_buff *skb,
	       struct nf_hook_state *state,
	       const struct nf_hook_entries *e)
{
	return enter_nf_hook_slow(state, e);
}

SEC("fexit/nf_hook_slow")
int BPF_PROG(nf_hook_slow_ret, struct sk_buff *skb, struct nf_hook_state *state,
	     const struct nf_hook_entries *e, unsigned int s, long ret)
{
	return exit_nf_hook_slow(ctx, ret < 0 ? 0 : ret);
}

SEC("kretprobe/nf_hook_slow")
int BPF_KRETPROBE(nf_hook_slow_ret_kprobe, int ret)
{
	return exit_nf_hook_slow(ctx, ret < 0 ? 0 : ret);
}

SEC("kprobe/ipv4_conntrack_defrag")
int BPF_KPROBE(ipv4_conntrack_defrag_kprobe)
{
	return enter_hook(ctx);
}

SEC("kretprobe/ipv4_conntrack_defrag")
int BPF_KRETPROBE(ipv4_conntrack_defrag_ret_kprobe, unsigned int verdict)
{
	return exit_hook(verdict);
}

SEC("kprobe/iptable_raw_hook")
int BPF_KPROBE(iptable_raw_hook_kprobe)
{
	return enter_hook(ctx);
}

SEC("kretprobe/iptable_raw_hook")
int BPF_KRETPROBE(iptable_raw_hook_ret_kprobe, unsigned int verdict)
{
	return exit_hook(verdict);
}

SEC("kprobe/ipv4_conntrack_in")
int BPF_KRETPROBE(ipv4_conntrack_in_kprobe)
{
	return enter_hook(ctx);
}

SEC("kretprobe/ipv4_conntrack_in")
int BPF_KRETPROBE(ipv4_conntrack_in_ret_kprobe, unsigned int verdict)
{
	return exit_hook(verdict);
}

SEC("kprobe/iptable_mangle_hook")
int BPF_KPROBE(iptable_mangle_hook_kprobe)
{
	return enter_hook(ctx);
}

SEC("kretprobe/iptable_mangle_hook")
int BPF_KRETPROBE(iptable_mangle_hook_ret_kprobe, unsigned int verdict)
{
	return exit_hook(verdict);
}

SEC("kprobe/nf_nat_ipv4_in")
int BPF_KPROBE(nf_nat_ipv4_in_kprobe)
{
	return enter_hook(ctx);
}

SEC("kretprobe/nf_nat_ipv4_in")
int BPF_KRETPROBE(nf_nat_ipv4_in_ret_kprobe, unsigned int verdict)
{
	return exit_hook(verdict);
}

SEC("kprobe/iptable_filter_hook")
int BPF_KPROBE(iptable_filter_hook_kprobe)
{
	return enter_hook(ctx);
}

SEC("kretprobe/iptable_filter_hook")
int BPF_KRETPROBE(iptable_filter_hook_ret_kprobe, unsigned int verdict)
{
	return exit_hook(verdict);
}

SEC("kprobe/iptable_security_hook")
int BPF_KPROBE(iptable_security_hook_kprobe)
{
	return enter_hook(ctx);
}

SEC("kretprobe/iptable_security_hook")
int BPF_KRETPROBE(iptable_security_hook_ret_kprobe, unsigned int verdict)
{
	return exit_hook(verdict);
}

SEC("kprobe/nf_nat_ipv4_fn")
int BPF_KPROBE(nf_nat_ipv4_fn_kprobe)
{
	return enter_hook(ctx);
}

SEC("kretprobe/nf_nat_ipv4_fn")
int BPF_KRETPROBE(nf_nat_ipv4_fn_ret_kprobe, unsigned int verdict)
{
	return exit_hook(verdict);
}

SEC("kprobe/ipv4_confirm")
int BPF_KPROBE(ipv4_confirm_kprobe)
{
	return enter_hook(ctx);
}

SEC("kretprobe/ipv4_confirm")
int BPF_KRETPROBE(ipv4_confirm_ret_kprobe, unsigned int verdict)
{
	return exit_hook(verdict);
}

SEC("kprobe/ipv4_conntrack_local")
int BPF_KPROBE(ipv4_conntrack_local_kprobe)
{
	return enter_hook(ctx);
}

SEC("kretprobe/ipv4_conntrack_local")
int BPF_KRETPROBE(ipv4_conntrack_local_ret_kprobe, unsigned int verdict)
{
	return exit_hook(verdict);
}

SEC("kprobe/nf_nat_ipv4_local_fn")
int BPF_KPROBE(nf_nat_ipv4_local_fn_kprobe)
{
	return enter_hook(ctx);
}

SEC("kretprobe/nf_nat_ipv4_local_fn")
int BPF_KRETPROBE(nf_nat_ipv4_local_fn_ret_kprobe, unsigned int verdict)
{
	return exit_hook(verdict);
}

SEC("kprobe/nf_nat_ipv4_out")
int BPF_KPROBE(nf_nat_ipv4_out_kprobe)
{
	return enter_hook(ctx);
}

SEC("kretprobe/nf_nat_ipv4_out")
int BPF_KRETPROBE(nf_nat_ipv4_out_ret_kprobe, unsigned int verdict)
{
	return exit_hook(verdict);
}

char LICENSE[] SEC("license") = "GPL";
