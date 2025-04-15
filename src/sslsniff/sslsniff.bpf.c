// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"
#include "compat.bpf.h"
#include "sslsniff.h"

const volatile pid_t target_pid = -1;
const volatile pid_t target_uid = -1;

#define BASE_EVENT_SIZE ((size_t)(&((struct probe_SSL_data_t*)0)->buf))
#define EVENT_SIZE(X) (BASE_EVENT_SIZE + ((size_t)(X)))

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} start_ns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} bufs SEC(".maps");

static __always_inline bool trace_allowed(u32 tid, u32 pid)
{
	if (target_pid != -1 && target_pid != pid)
		return false;
	if (target_uid != -1 && target_uid != tid)
		return false;
	return true;
}

static __always_inline int SSL_exit(struct pt_regs *ctx, int rw)
{
	struct probe_SSL_data_t *data = NULL;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = (__u32)pid_tgid;
	u32 uid = bpf_get_current_uid_gid();
	u64 ts = bpf_ktime_get_ns();
	u64 *bufp = NULL;
	u64 *tsp = NULL;
	u64 delta_ns;
	u32 buf_copy_size;
	int ret;
	int len = PT_REGS_RC(ctx);

	if (len <= 0) // no data
		return 0;

	if (!trace_allowed(uid, pid))
		return 0;

	bufp = bpf_map_lookup_elem(&bufs, &tid);
	if (!bufp)
		return 0;

	tsp = bpf_map_lookup_elem(&start_ns, &tid);
	if (!tsp)
		return 0;

	delta_ns = ts - *tsp;

	data = reserve_buf(EVENT_SIZE(MAX_BUF_SIZE));
	if (!data)
		return 0;

	data->timestamp_ns = ts;
	data->delta_ns = ts - *tsp;
	data->pid = pid;
	data->tid = tid;
	data->uid = uid;
	data->len = (u32)len;
	data->buf_filled = 0;
	data->rw = rw;
	buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)len);

	bpf_get_current_comm(&data->comm, sizeof(data->comm));
	ret = bpf_probe_read_user(&data->buf, buf_copy_size, (char *)*bufp);
	if (!ret)
		data->buf_filled = 1;
	else
		buf_copy_size = 0;

	bpf_map_delete_elem(&bufs, &tid);
	bpf_map_delete_elem(&start_ns, &tid);

	submit_buf(ctx, data, EVENT_SIZE(buf_copy_size));

	return 0;
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_SSL_rw_enter, void *ssl, void *buf, int num)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = pid_tgid;
	u32 uid = bpf_get_current_uid_gid();
	u64 ts = bpf_ktime_get_ns();

	if (!trace_allowed(uid, pid))
		return 0;

	bpf_map_update_elem(&bufs, &tid, &buf, BPF_ANY);
	bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);

	return 0;
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(probe_SSL_write_exit)
{
	return SSL_exit(ctx, 1);
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(probe_SSL_read_exit)
{
	return SSL_exit(ctx, 0);
}

SEC("uprobe/do_handshake")
int BPF_UPROBE(probe_SSL_do_handshake_enter, void *ssl)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = (u32)pid_tgid;
	u64 ts = bpf_ktime_get_ns();
	u32 uid = bpf_get_current_uid_gid();

	if (!trace_allowed(uid, pid))
		return 0;

	bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);

	return 0;
}

SEC("uretprobe/do_handshake")
int BPF_URETPROBE(probe_SSL_do_handshake_exit)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = (u32)pid_tgid;
	u32 uid = bpf_get_current_uid_gid();
	u64 ts = bpf_ktime_get_ns();
	u64 *tsp = NULL;
	struct probe_SSL_data_t *data = NULL;
	int ret;

	if (!trace_allowed(uid, pid))
		return 0;

	tsp = bpf_map_lookup_elem(&start_ns, &tid);
	if (!tsp)
		return 0;

	ret = PT_REGS_RC(ctx);
	if (ret <= 0) //handshake failed
		return 0;

	data = reserve_buf(EVENT_SIZE(0));
	if (!data)
		return 0;

	data->timestamp_ns = ts;
	data->delta_ns = ts - *tsp;
	data->pid = pid;
	data->tid = tid;
	data->uid = uid;
	data->len = ret;
	data->buf_filled = 0;
	data->rw = 2;
	bpf_get_current_comm(&data->comm, sizeof(data->comm));
	bpf_map_delete_elem(&start_ns, &tid);

	submit_buf(ctx, data, EVENT_SIZE(0));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
