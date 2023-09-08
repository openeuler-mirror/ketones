// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Based on uflow.py - Sasha Goldshtein

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"
#include "compat.bpf.h"
#include "uflow.h"

const volatile pid_t target_pid = -1;
const volatile int target_language = LA_NONE;
const volatile int target_class_sz = 0;
const volatile int target_method_sz = 0;
const volatile bool filter_class = false;
const volatile bool filter_method = false;

char target_class[MAX_STRING_LEN] = {};
char target_method[MAX_STRING_LEN] = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, __u64);
} entry SEC(".maps");

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

static __always_inline bool class_matched(const char *actual)
{
	if (!filter_class)
		return true;

	for (int i = 0; i < target_class_sz && i < MAX_STRING_LEN; ++i) {
		if (target_class[i] != actual[i]) {
			return false;
		}
	}
	return true;
}

static __always_inline bool method_matched(const char *actual)
{
	if (!filter_method)
		return true;

	for (int i = 0; i < target_method_sz && i < MAX_STRING_LEN; ++i) {
		if (target_method[i] != actual[i]) {
			return false;
		}
	}
	return true;
}

static void read_args(void *ctx, long *arg, bool method)
{
	if (method && !languages[target_language].method)
		return;

	if (method)
		bpf_usdt_arg(ctx, languages[target_language].method - 1, arg);
	else
		bpf_usdt_arg(ctx, languages[target_language].clazz - 1, arg);
}

static int trace_common(void *ctx, bool is_return)
{
	__u64 *depth, zero = 0, clazz = 0, method = 0;
	__u64 pid;
	struct call_t *e;

	pid = bpf_get_current_pid_tgid();

	e = reserve_buf(sizeof(struct call_t));
	if (!e)
		return 0;

	read_args(ctx, (long *)&clazz, false);
	read_args(ctx, (long *)&method, true);

	bpf_probe_read(e->clazz, sizeof(e->clazz),
			(void *)clazz);
	bpf_probe_read(e->method, sizeof(e->method),
			(void *)method);

	/* filter */
	if (!class_matched(e->clazz)) {
		discard_buf(e);
		return 0;
	}
	if (!method_matched(e->method)) {
		discard_buf(e);
		return 0;
	}

	e->pid = pid;
	e->cpu = bpf_get_smp_processor_id();
	depth = bpf_map_lookup_or_try_init(&entry, &pid, &zero);
	if (!depth)
		depth = &zero;

	if (!is_return){
		e->depth = *depth + 1;
		++(*depth);
	} else {
		e->depth = *depth | (1ULL << 63);
		if (*depth)
			--(*depth);
	}
	submit_buf(ctx, e, sizeof(struct call_t));
	return 0;
}

SEC("usdt")
int BPF_USDT(trace_entry)
{
	return trace_common(ctx, false);
}

SEC("usdt")
int BPF_USDT(trace_return)
{
	return trace_common(ctx, true);
}

char LICENSE[] SEC("license") = "GPL";
