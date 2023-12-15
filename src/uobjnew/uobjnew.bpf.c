// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>
#include <bpf/bpf_core_read.h>
#include "uobjnew.h"
#include "maps.bpf.h"

#define min(x, y) ((x) < (y) ? (x) : (y))

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_EVENTS_ENTRY);
	__type(key, struct key_t);
	__type(value, struct val_t);
} uobjnew_events_entry SEC(".maps");

static __always_inline int handle_alloc(struct key_t *key, __u64 size)
{
	struct val_t *valp, zero = {};

	valp = bpf_map_lookup_or_try_init(&uobjnew_events_entry, key, &zero);
	if (valp) {
		valp->total_size += size;
		valp->num_allocs += 1;
	}
	return 0;
}

#define HANDLE_RUBY(prefix) \
static __always_inline int do_handle_ruby_alloc_##prefix(struct pt_regs *ctx) \
{  \
	struct key_t key = { .key.name = #prefix };  \
	long size = 0;  \
	\
	bpf_usdt_arg(ctx, 0, (long *)&size);  \
	return handle_alloc(&key, size);  \
}

HANDLE_RUBY(string);
HANDLE_RUBY(hash);
HANDLE_RUBY(array);

SEC("uprobe")
int handle_c_alloc(struct pt_regs *ctx)
{
	struct key_t key = {};
	key.key.size = PT_REGS_PARM1(ctx);

	return handle_alloc(&key, key.key.size);
}

SEC("usdt")
int handle_java_alloc(struct pt_regs *ctx)
{
	struct key_t key = {};
	u64 classptr = 0, size = 0;
	u64 length = 0;

	bpf_usdt_arg(ctx, 1, (long *)&classptr);
	bpf_usdt_arg(ctx, 2, (long *)&length);
	bpf_usdt_arg(ctx, 3, (long *)&size);

	bpf_probe_read_user_str(key.key.name, min(sizeof(key.key.name), length),
				(void *)classptr);

	handle_alloc(&key, key.key.size);

	return 0;
}

SEC("usdt")
int handle_ruby_alloc(struct pt_regs *ctx)
{
	struct key_t key = {};
	u64 classptr = 0;

	bpf_usdt_arg(ctx, 0, (long *)&classptr);
	bpf_probe_read_user_str(&key.key.name, sizeof(key.key.name),
					(void *)classptr);

	handle_alloc(&key, 0); // We don't know the size, unfortunately

	return 0;
}

SEC("usdt")
int handle_ruby_alloc_string(struct pt_regs *ctx)
{
	return do_handle_ruby_alloc_string(ctx);
}

SEC("usdt")
int handle_ruby_alloc_hash(struct pt_regs *ctx)
{
	return do_handle_ruby_alloc_hash(ctx);
}

SEC("usdt")
int handle_ruby_alloc_array(struct pt_regs *ctx)
{
	return do_handle_ruby_alloc_array(ctx);
}

SEC("usdt")
int handle_tcl_alloc(struct pt_regs *ctx)
{
	struct key_t key = { .key.name = "<ALL>" };

	return handle_alloc(&key, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
