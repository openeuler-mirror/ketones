// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"
#include "compat.bpf.h"
#include "mysqld-qslower.h"

const volatile __u64 min_ns = 1000000;
const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct start_t);
} start_tmp SEC(".maps");

SEC("usdt")
int BPF_USDT(do_start)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct start_t start = {};

	if (pid != target_pid)
		return 0;

	start.ts = bpf_ktime_get_ns();
	bpf_usdt_arg(ctx, 0, (long *)&start.query);
	bpf_map_update_elem(&start_tmp, &tid, &start, BPF_NOEXIST);

	return 0;
}

SEC("usdt")
int BPF_USDT(do_done)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct start_t *sp;
	struct data_t *data;

	sp = bpf_map_lookup_elem(&start_tmp, &tid);
	if (!sp)
		return 0;

	__u64 delta = bpf_ktime_get_ns() - sp->ts;
	if (delta >= min_ns) {
		data = reserve_buf(sizeof(*data));
		if (!data)
			return 0;

		data->pid = pid,
		data->delta = delta;
		bpf_probe_read_user_str(&data->query, sizeof(data->query),
					(void *)sp->query);

		submit_buf(ctx, data, sizeof(*data));
	}
	bpf_map_delete_elem(&start_tmp, &tid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
