// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>
#include <bpf/bpf_core_read.h>
#include "dbslower.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

const volatile __u64 db_mode = 0;
const volatile __u64 threshold = 0;

struct start_t {
	union {
		char *pquery;
		//MySQL clears query packet before uretprobe call - so copy query in advance
		char query[256];
	} q;
	__u64 timestamp;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct start_t);
} temp SEC(".maps");

static __always_inline int query_start(struct pt_regs *ctx)
{
	__u64 command;
	struct start_t tmp = {};
	__u64 pid = bpf_get_current_pid_tgid();

	if (db_mode == DB_MODE_MYSQL56 || db_mode == DB_MODE_MYSQL57) {
		if (db_mode == DB_MODE_MYSQL56)
			command = (__u64)PT_REGS_PARM1(ctx);

		if (db_mode == DB_MODE_MYSQL57)
			command = (__u64)PT_REGS_PARM3(ctx);

		if (command != 3)
			return 0;
	}

	if (db_mode == DB_MODE_MYSQL56) {
		bpf_probe_read_user_str(&tmp.q.query, sizeof(tmp.q.query), (void *)PT_REGS_PARM3(ctx));
	} else if (db_mode == DB_MODE_MYSQL57) {
		char *query;
		bpf_probe_read_user(&query, sizeof(query), (void *)PT_REGS_PARM2(ctx));
		bpf_probe_read_user_str(&tmp.q.query, sizeof(tmp.q.query), query);
	} else {
		bpf_usdt_arg(ctx, 0, (long *)(&tmp.q.pquery));
	}

	tmp.timestamp = bpf_ktime_get_ns();
	bpf_map_update_elem(&temp, &pid, &tmp, BPF_NOEXIST);

	return 0;
}

static __always_inline int query_end(struct pt_regs *ctx)
{
	struct start_t *tempp;
	__u64 pid = bpf_get_current_pid_tgid();
	struct data_t *data;
	__u64 delta;

	tempp = bpf_map_lookup_elem(&temp, &pid);
	if (!tempp)
		return 0;

	delta = bpf_ktime_get_ns() - tempp->timestamp;
	if (!threshold || delta >= threshold) {
		data = reserve_buf(sizeof(*data));
		if (!data)
			return 0;

		data->pid = pid >> 32;  //only process id
		data->duration = delta;

		if (db_mode == DB_MODE_MYSQL56 || db_mode == DB_MODE_MYSQL57)
			bpf_probe_read_kernel(&data->query, sizeof(data->query), tempp->q.query);
		else
			bpf_probe_read_user_str(&data->query, sizeof(data->query), tempp->q.pquery);

		submit_buf(ctx, data, sizeof(*data));
	}
	bpf_map_delete_elem(&temp, &pid);

	return 0;
}

SEC("usdt")
int BPF_USDT(query_start_usdt)
{
	return query_start(ctx);
}

SEC("usdt")
int BPF_USDT(query_end_usdt)
{
	return query_end(ctx);
}

SEC("uprobe")
int query_start_uprobe(struct pt_regs *ctx)
{
	return query_start(ctx);
}

SEC("uprobe")
int query_end_uprobe(struct pt_regs *ctx)
{
	return query_end(ctx);
}

char LICENSE[] SEC("license") = "GPL";
