// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on uthreads.py - Sasha Goldshtein

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"
#include "compat.bpf.h"
#include "uthreads.h"

static __always_inline void trace_thread(struct pt_regs *ctx, const char *type)
{
	struct thread_event_t *te;
	long nameptr = 0, id = 0, native_id = 0;

	te = reserve_buf(sizeof(*te));
	if (!te)
		return;

	__builtin_memcpy(&te->type, type, sizeof(te->type));
	bpf_usdt_arg(ctx, 0, &nameptr);
	bpf_usdt_arg(ctx, 2, &id);
	bpf_usdt_arg(ctx, 3, &native_id);
	bpf_probe_read_user_str(&te->name, sizeof(te->name), (void *)nameptr);
	te->runtime_id = id;
	te->native_id = native_id;
	submit_buf(ctx, te, sizeof(*te));
}

SEC("usdt")
int BPF_USDT(trace_pthread)
{
	struct thread_event_t *te;
	long id = 0;

	te = reserve_buf(sizeof(*te));
	if (!te)
		return 0;

	__builtin_memcpy(&te->type, "pthread", sizeof(te->type));
	te->native_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	bpf_usdt_arg(ctx, 1, &id);
	te->runtime_id = id;
	submit_buf(ctx, te, sizeof(*te));

	return 0;
}

SEC("usdt")
int BPF_USDT(trace_start)
{
	trace_thread(ctx, "start");

	return 0;
}

SEC("usdt")
int BPF_USDT(trace_stop)
{
	trace_thread(ctx, "stop");

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
