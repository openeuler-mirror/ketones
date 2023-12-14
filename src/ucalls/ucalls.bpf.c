// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Based on ucalls.py - Sasha Goldshtein

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"
#include "ucalls.h"

const volatile bool do_latency = false;
const volatile bool nolang = false;
const volatile bool do_syscalls = false;
const volatile pid_t target_pid = -1;
const volatile int target_language = LA_NONE;

struct entry_t {
	__u64 pid;
	struct method_t method;
};

struct syscall_entry_t {
	__u64 timestamp;
	__u64 id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct method_t);
	__type(value, __u64);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, __u64);
} syscounts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct method_t);
	__type(value, struct info_t);
} times SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct entry_t);
	__type(value, __u64);
} entry SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct info_t);
} systimes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct syscall_entry_t);
} sysentry SEC(".maps");

struct {
	int clazz;
	int method;
} languages[] = {
	[LA_JAVA] = {
		.clazz = 2,
		.method = 4,
	},
	[LA_PERL] = {
		.clazz = 2,
		.method = 1,
	},
	[LA_PHP] = {
		.clazz = 4,
		.method = 1,
	},
	[LA_PYTHON] = {
		.clazz = 1,
		.method = 2,
	},
	[LA_RUBY] = {
		.clazz = 1,
		.method = 2,
	},
	[LA_TCL] = {
		.method = 1,
	},
};

static void read_args(void *ctx, long *arg, bool method)
{
	if (method && !languages[target_language].method)
		return;

	if (method)
		bpf_usdt_arg(ctx, languages[target_language].method - 1, arg);
	else
		bpf_usdt_arg(ctx, languages[target_language].clazz - 1, arg);
}

SEC("usdt")
int BPF_USDT(trace_entry)
{
	long clazz = 0, method = 0;
	struct entry_t data = {};
	__u64 timestamp;

	if (do_latency) {
		timestamp = bpf_ktime_get_ns();
		data.pid = bpf_get_current_pid_tgid();
	}

	read_args(ctx, &clazz, false);
	read_args(ctx, &method, true);

	bpf_probe_read(&data.method.clazz, sizeof(data.method.clazz),
		       (void *)clazz);
	bpf_probe_read(&data.method.method, sizeof(data.method.method),
		       (void *)method);

	if (!do_latency) {
		__u64 zero = 0, *valp;

		valp = bpf_map_lookup_or_try_init(&counts, &data.method, &zero);
		if (!valp)
			return 0;

		(*valp)++;
	} else {
		bpf_map_update_elem(&entry, &data, &timestamp, BPF_ANY);
	}

	return 0;
}

SEC("usdt")
int BPF_USDT(trace_return)
{
	__u64 *entry_timestamp;
	long clazz = 0, method = 0;
	struct info_t *info, zero = {};
	struct entry_t data = {};

	data.pid = bpf_get_current_pid_tgid();

	read_args(ctx, &clazz, false);
	read_args(ctx, &method, true);

	bpf_probe_read(&data.method.clazz, sizeof(data.method.clazz),
		       (void *)clazz);
	bpf_probe_read(&data.method.method, sizeof(data.method.method),
		       (void *)method);

	entry_timestamp = bpf_map_lookup_and_delete_elem(&entry, &data);
	if (!entry_timestamp)
		return 0;

	info = bpf_map_lookup_or_try_init(&times, &data.method, &zero);
	if (!info)
		return 0;

	info->num_calls += 1;
	info->total_ns += bpf_ktime_get_ns() - *entry_timestamp;

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint_syscall_enter(struct trace_event_raw_sys_enter *args)
{
	__u64 pid = bpf_get_current_pid_tgid();
	__u64 id = args->id;

	if (target_pid != -1 && target_pid != (pid >> 32))
		return 0;

	if (do_latency) {
		struct syscall_entry_t data = {};

		data.timestamp = bpf_ktime_get_ns();
		data.id = id;
		bpf_map_update_elem(&sysentry, &pid, &data, BPF_ANY);
	} else {
		__u64 *valp, zero = 0;

		valp = bpf_map_lookup_or_try_init(&syscounts, &id, &zero);
		if (!valp)
			return 0;

		(*valp)++;
	}

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint_syscall_exit(struct trace_event_raw_sys_exit *args)
{
	__u64 pid = bpf_get_current_pid_tgid();
	struct syscall_entry_t *e;
	struct info_t *infop, zero = {};

	if (target_pid != -1 && target_pid != (pid >> 32))
		return 0;

	e = bpf_map_lookup_and_delete_elem(&sysentry, &pid);
	if (!e)
		return 0;

	infop = bpf_map_lookup_or_try_init(&systimes, &e->id, &zero);
	if (!infop)
		return 0;

	infop->num_calls += 1;
	infop->total_ns += bpf_ktime_get_ns() - e->timestamp;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
