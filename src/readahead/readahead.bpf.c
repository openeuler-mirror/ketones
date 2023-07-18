// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "readahead.h"
#include "bits.bpf.h"

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} in_readahead SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, void *);
	__type(value, u64);
} birth SEC(".maps");

struct hist hist = {};

SEC("fentry/do_page_cache_ra")
int BPF_PROG(do_page_cache_ra)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 one = 1;

	bpf_map_update_elem(&in_readahead, &pid, &one, BPF_ANY);
	return 0;
}

SEC("kprobe/do_page_cache_ra")
int BPF_KPROBE(do_page_cache_ra_kprobe)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 one = 1;

	bpf_map_update_elem(&in_readahead, &pid, &one, BPF_ANY);
	return 0;
}

static __always_inline int alloc_page_ret(void *key)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 ts;

	if (!bpf_map_lookup_elem(&in_readahead, &pid))
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&birth, &key, &ts, BPF_ANY);
	__sync_fetch_and_add(&hist.unused, 1);
	__sync_fetch_and_add(&hist.total, 1);

	return 0;
}

SEC("fexit/__page_cache_alloc")
int BPF_PROG(page_cache_alloc_ret, gfp_t gfp, struct page *page)
{
	return alloc_page_ret(page);
}

SEC("kretprobe/__page_cache_alloc")
int BPF_KRETPROBE(page_cache_alloc_kretprobe, struct page *page)
{
	return alloc_page_ret(page);
}

SEC("fexit/filemap_alloc_folio")
int BPF_PROG(filemap_alloc_folio_ret, gfp_t gfp, unsigned int order,
	     struct folio *folio)
{
	return alloc_page_ret(folio);
}

SEC("kretprobe/filemap_alloc_folio")
int BPF_KRETPROBE(filemap_alloc_folio_kretprobe, struct folio *folio)
{
	return alloc_page_ret(folio);
}

SEC("fexit/do_page_cache_ra")
int BPF_PROG(do_page_cache_ra_ret)
{
	u32 pid = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&in_readahead, &pid);
	return 0;
}

SEC("kretprobe/do_page_cache_ra")
int BPF_KRETPROBE(do_page_cache_ra_kretprobe)
{
	u32 pid = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&in_readahead, &pid);
	return 0;
}

static __always_inline int page_accessed_entry(void *key)
{
	u64 *tsp, slot, ts = bpf_ktime_get_ns();
	s64 delta;

	tsp = bpf_map_lookup_elem(&birth, &key);
	if (!tsp)
		return 0;

	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto update_and_cleanup;
	slot = log2l(delta / 1000000U);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hist.slots[slot], 1);

update_and_cleanup:
	__sync_fetch_and_add(&hist.unused, -1);
	bpf_map_delete_elem(&birth, &key);

	return 0;
}

SEC("fentry/mark_page_accessed")
int BPF_PROG(mark_page_accessed, struct page *page)
{
	return page_accessed_entry(page);
}

SEC("kprobe/mark_page_accessed")
int BPF_KPROBE(mark_page_accessed_kprobe, struct page *page)
{
	return page_accessed_entry(page);
}

SEC("fentry/folio_mark_accessed")
int BPF_PROG(folio_mark_accessed, struct folio *folio)
{
	return page_accessed_entry(folio);
}

SEC("kprobe/folio_mark_accessed")
int BPF_KPROBE(folio_mark_accessed_kprobe, struct folio *folio)
{
	return page_accessed_entry(folio);
}

char LICENSE[] SEC("license") = "GPL";
