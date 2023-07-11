// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "numasched.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 10240);
} numa_node_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

const volatile pid_t target_tgid = INVALID_PID;
const volatile pid_t target_pid = INVALID_PID;

static int handle_sched_switch(void *ctx, struct task_struct *prev,
			       struct task_struct *next)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t tgid = id >> 32;
	pid_t pid = (pid_t)id;
	u32 numa_id = bpf_get_numa_node_id();
	u32 *old_numa_id;

	if (tgid == 0)
		return 0;

	if (target_tgid != INVALID_PID && target_tgid != tgid)
		return 0;

	if (target_pid != INVALID_PID && target_pid != pid)
		return 0;

	old_numa_id = bpf_map_lookup_elem(&numa_node_map, &pid);
	if (!old_numa_id)
		goto update;

	if (*old_numa_id != numa_id) {
		/* record event */
		struct event event;

		event.pid = tgid;
		event.tid = pid;
		bpf_get_current_comm(&event.comm, sizeof(event.comm));
		event.prev_numa_node_id = *old_numa_id;
		event.numa_node_id = numa_id;

		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
				      sizeof(struct event));
	}

update:
	bpf_map_update_elem(&numa_node_map, &pid, &numa_id, BPF_ANY);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_btf, int preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return handle_sched_switch(ctx, prev, next);
}

SEC("raw_tp/sched_switch")
int BPF_PROG(sched_switch_raw, int preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return handle_sched_switch(ctx, prev, next);
}

char LICENSE[] SEC("license") = "GPL";
