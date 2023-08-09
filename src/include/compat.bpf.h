// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

#ifndef __COMPAT_BPF_H
#define __COMPAT_BPF_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_EVENT_SIZE		10240
#define RINGBUF_SIZE		(1024 * 256)

#ifndef __has_builtin		// Optional of course.
  #define __has_builtin(x) 0	// Compatibility with non-clang compilers.
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_EVENT_SIZE);
} heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

/*
 * In some systems, ringbuf support is backported, but because clang does not
 * support bpf_core_type_exists (clang < 12), it is impossible to correctly
 * determine whether ringbuf is supported, and identify whether ringbuf is
 * supported through certain workarounds.
 * see:
 *    https://github.com/torvalds/linux/commit/457f44363a88
 */
struct bpf_reg_state___x {
	u32 mem_size;
} __attribute__((preserve_access_index));

static __always_inline bool has_ringbuf(void)
{
#if __has_builtin(__builtin_preserve_type_info)
	if (bpf_core_type_exists(struct bpf_ringbuf))
		return true;
#endif
	if (bpf_core_field_exists(struct bpf_reg_state___x, mem_size))
		return true;

	return false;
}

static __always_inline void *reserve_buf(__u64 size)
{
	static const int zero = 0;

	if (has_ringbuf())
		return bpf_ringbuf_reserve(&events, size, 0);

	return bpf_map_lookup_elem(&heap, &zero);
}

static __always_inline void *discard_buf(void *buf)
{
	static const int zero = 0;

	if (has_ringbuf()) {
		bpf_ringbuf_discard(buf, 0);
		return 0;
	}

	bpf_map_delete_elem(&heap, &zero);
	return 0;
}

static __always_inline long submit_buf(void *ctx, void *buf, __u64 size)
{
	if (has_ringbuf()) {
		bpf_ringbuf_submit(buf, 0);
		return 0;
	}

	return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, buf, size);
}

#endif /* __COMPAT_BPF_H */
