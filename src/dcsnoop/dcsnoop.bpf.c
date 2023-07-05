// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "dcsnoop.h"
#include "compat.bpf.h"
#include "maps.bpf.h"

const volatile pid_t target_pid = 0;
const volatile pid_t target_tid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, struct entry_t);
} entrys SEC(".maps");

static __always_inline int
trace_fast(void *ctx, struct nameidata *nd, struct path *path)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32, tid = pid_tgid;
	struct event *event;

	if (target_pid && target_pid != pid)
		return 0;
	if (target_tid && target_tid != tid)
		return 0;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->pid = pid;
	event->tid = tid;
	event->type = LOOKUP_REFERENCE;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	const unsigned char *name = BPF_CORE_READ(nd, last.name);
	bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), name);

	submit_buf(ctx, event, sizeof(*event));
	return 0;
}

static __always_inline int
kprobe__d_lookup(void *ctx, const struct dentry *parent,
		 const struct qstr *name)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = pid_tgid;
	struct entry_t entry = {};

	if (target_pid && target_pid != pid)
		return 0;
	if (target_tid && target_tid != tid)
		return 0;

	const unsigned char *t_name = BPF_CORE_READ(name, name);
	bpf_probe_read_kernel_str(&entry.name, sizeof(entry.name), t_name);
	bpf_map_update_elem(&entrys, &tid, &entry, BPF_ANY);
	return 0;
}

static __always_inline int kretprobe__d_lookup(void *ctx, struct dentry *ret)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = pid_tgid;
	struct entry_t *ep;
	struct event *event;

	if (ret != NULL)	/* lookup didn't fail */
		return 0;

	ep = bpf_map_lookup_and_delete_elem(&entrys, &tid);
	if (!ep)
		return 0;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->pid = pid;
	event->tid = tid;
	event->type = LOOKUP_MISS;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	BPF_PROBE_READ_STR_INTO(&event->filename, ep, name);

	submit_buf(ctx, event, sizeof(*event));
	return 0;
}

static __always_inline int
fexit__d_lookup(void *ctx, const struct dentry *parent,
		const struct qstr *name, struct dentry *ret)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = pid_tgid;
	struct event *event;

	if (ret != NULL)	/* lookup didn't fail */
		return 0;

	if (target_pid && target_pid != pid)
		return 0;
	if (target_tid && target_tid != tid)
		return 0;

	event = reserve_buf(sizeof(*event));
	if (!event)
		return 0;

	event->pid = pid;
	event->tid = tid;
	event->type = LOOKUP_MISS;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	bpf_core_read_str(&event->filename, sizeof(event->filename), name->name);

	submit_buf(ctx, event, sizeof(*event));
	return 0;
}

SEC("fentry/lookup_fast")
int BPF_PROG(lookup_fast_fentry, struct nameidata *nd, struct path *path)
{
	return trace_fast(ctx, nd, path);
}

SEC("kprobe/lookup_fast")
int BPF_KPROBE(lookup_fast_kprobe, struct nameidata *nd, struct path *path)
{
	return trace_fast(ctx, nd, path);
}

SEC("fexit/d_lookup")
int BPF_PROG(d_lookup_fexit, const struct dentry *parent,
	     const struct qstr *name, struct dentry *ret)
{
	return fexit__d_lookup(ctx, parent, name, ret);
}

SEC("kprobe/d_lookup")
int BPF_KPROBE(d_lookup_kprobe, const struct dentry *parent,
	       const struct qstr *name)
{
	return kprobe__d_lookup(ctx, parent, name);
}

SEC("kretprobe/d_lookup")
int BPF_KRETPROBE(d_lookup_kretprobe, struct dentry *ret)
{
	return kretprobe__d_lookup(ctx, ret);
}

char LICENSE[] SEC("license") = "GPL";
