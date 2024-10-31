// SPDX-License-Identifier: GPL-2.0
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on criticalstat.py - Joel Fernandes

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "criticalstat.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

const volatile int duration = 0;

enum addr_offs {
	START_CALLER_OFF,
	START_PARENT_OFF,
	END_CALLER_OFF,
	END_PARENT_OFF
};

struct start_data {
	u32 addr_offs[2];
	u64 ts;
	int idle_skip;
	int active;
};

struct trace_event_raw_preemptirq_template {
	struct trace_entry ent;
	s32 caller_offs;
	s32 parent_offs;
	char __data[0];
};

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, unsigned long[PERF_MAX_STACK_DEPTH]);
} stack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct start_data);
} sts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} isidle SEC(".maps");

/*
 * In the below code we install tracepoint probes on preempt or
 * IRQ disable/enable critical sections and idle events, the cases
 * are combinations of 4 different states.
 * The states are defined as:
 * CSenter: A critical section has been entered. Either due to
 * 	    preempt disable or irq disable.
 * CSexit: A critical section has been exited. Either due to
 * 	   preempt enable or irq enable.
 * Ienter: The CPU has entered an idle state.
 * Iexit: The CPU has exited an idle state.
 *
 * The scenario we are trying to detect is if there is an overlap
 * between Critical sections and idle entry/exit. If there are any
 * such cases, we avoid recording those critical sections since they
 * are not worth while to record and just add noise.
 */

SEC("tracepoint/power/cpu_idle")
int cpu_idle_entry(struct trace_event_raw_cpu *ctx)
{
	int idx = 0;
	u64 val;
	struct start_data *stdp, std;
	unsigned int state = (unsigned int)ctx->state;

	// Mark active sections as that they should be skipped

	// Handle the case CSenter, Ienter, CSexit, Iexit
	// Handle the case CSenter, Ienter, Iexit, CSexit
	stdp = bpf_map_lookup_elem(&sts, &idx);
	if (stdp && stdp->active) {
		/*
		 * Due to verifier issues, we have to copy contents
		 * of stdp onto the stack before the update.
		 * Fix it to directly update once kernel patch d71962f
		 * becomes more widespread.
		 */
		__builtin_memcpy(&std, stdp, sizeof(struct start_data));
		std.idle_skip = 1;
		bpf_map_update_elem(&sts, &idx, &std, BPF_ANY);
	}

	// Mark CPU as actively within idle or not.
	if (state < 100)
		val = 1;
	else
		val = 0;
	bpf_map_update_elem(&isidle, &idx, &val, BPF_ANY);

	return 0;
}

static __always_inline bool in_idle(void)
{
	u64 *idlep;
	int idx = 0;

	// Skip event if we're in idle loop
	idlep = bpf_map_lookup_elem(&isidle, &idx);
	if (idlep && *idlep)
		return true;
	return false;
}

static __always_inline void reset_state(void)
{
	int idx = 0;
	struct start_data s = {};

	bpf_map_update_elem(&sts, &idx, &s, BPF_ANY);
}

static int
handle_disable(struct trace_event_raw_preemptirq_template *args)
{
	int idx = 0;
	struct start_data sd;

	// Handle the case Ienter, CSenter, CSexit, Iexit
	// Handle the case Ienter, CSenter, Iexit, CSexit
	if (in_idle()) {
		reset_state();
		return 0;
	}

	u64 ts = bpf_ktime_get_ns();
	sd.idle_skip = 0;
	sd.addr_offs[START_CALLER_OFF] = args->caller_offs;
	sd.addr_offs[START_PARENT_OFF] = args->parent_offs;
	sd.ts = ts;
	sd.active = 1;
	bpf_map_update_elem(&sts, &idx, &sd, BPF_ANY);

	return 0;
}

static int
handle_enable(struct trace_event_raw_preemptirq_template *args)
{
	int idx = 0;
	u64 start_ts, end_ts, diff;
	struct start_data *stdp;
	struct data_t *data;
	void *ctx = (void *)args;

	// Handle the case CSenter, Ienter, CSexit, Iexit
	// Handle the case Ienter, CSenter, CSexit, Iexit
	if (in_idle())
		goto out;

	stdp = bpf_map_lookup_elem(&sts, &idx);
	if (!stdp)
		goto out;

	// Handle the case Ienter, Csenter, Iexit, Csexit
	if (!stdp->active)
		goto out;

	// Handle the case CSenter, Ienter, Iexit, CSexit
	if (stdp->idle_skip)
		goto out;

	end_ts = bpf_ktime_get_ns();
	start_ts = stdp->ts;
	if (start_ts > end_ts)
		goto out;

	diff = end_ts - start_ts;
	if (duration && diff < duration)
		goto out;

	data = reserve_buf(sizeof(*data));
	if (!data)
		goto out;

	bpf_get_current_comm(&data->comm, sizeof(data->comm));
	data->addrs[START_CALLER_OFF] = stdp->addr_offs[START_CALLER_OFF];
	data->addrs[START_PARENT_OFF] = stdp->addr_offs[START_PARENT_OFF];
	data->addrs[END_CALLER_OFF] = args->caller_offs;
	data->addrs[END_PARENT_OFF] = args->parent_offs;
	data->id = bpf_get_current_pid_tgid();
	data->stack_id = bpf_get_stackid(ctx, &stack, 0);
	data->time = diff;
	data->cpu = bpf_get_smp_processor_id();
	submit_buf(ctx, data, sizeof(*data));
out:
	reset_state();

	return 0;
}

SEC("tracepoint/preemptirq/preempt_disable")
int preempt_disable_entry(struct trace_event_raw_preemptirq_template *ctx)
{
	return handle_disable(ctx);
}

SEC("tracepoint/preemptirq/preempt_enable")
int preempt_enable_entry(struct trace_event_raw_preemptirq_template *ctx)
{
	return handle_enable(ctx);
}

SEC("tracepoint/preemptirq/irq_disable")
int irq_disable_entry(struct trace_event_raw_preemptirq_template *ctx)
{
	return handle_disable(ctx);
}

SEC("tracepoint/preemptirq/irq_enable")
int irq_enable_entry(struct trace_event_raw_preemptirq_template *ctx)
{
	return handle_enable(ctx);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
