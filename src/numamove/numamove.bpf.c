// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "maps.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

__u64 latency = 0;
__u64 num = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} latency_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} num_map SEC(".maps");

static int __migrate_misplaced(void)
{
	pid_t pid = (pid_t)bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
	return 0;
}

SEC("fentry/migrate_misplaced_page")
int BPF_PROG(fentry_migrate_misplaced_page)
{
	return __migrate_misplaced();
}

SEC("fentry/migrate_misplaced_folio")
int BPF_PROG(fentry_migrate_misplaced_folio)
{
	return __migrate_misplaced();
}

SEC("kprobe/migrate_misplaced_page")
int BPF_KPROBE(kprobe_migrate_misplaced_page)
{
	return __migrate_misplaced();
}

SEC("kprobe/migrate_misplaced_filio")
int BPF_KPROBE(kprobe_migrate_misplaced_folio)
{
	return __migrate_misplaced();
}

static u64 zero;

static int __migrate_misplaced_exit(void)
{
	pid_t pid = (pid_t)bpf_get_current_pid_tgid();
	s64 delta;
	u64 *tsp, *value;
	u32 key = 0;

	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp)
		return 0;

	delta = (s64)(bpf_ktime_get_ns() - *tsp);
	if (delta < 0)
		goto cleanup;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
	__sync_fetch_and_add(&latency, delta / 1000000UL);
	__sync_fetch_and_add(&num, 1);
#else
	value = bpf_map_lookup_or_try_init(&latency_map, &key, &zero);
	if (!value)
		goto cleanup;
	__sync_fetch_and_add(value, delta / 1000000UL);

	value = bpf_map_lookup_or_try_init(&num_map, &key, &zero);
	if (!value)
		goto cleanup;
	__sync_fetch_and_add(value, 1);
#endif

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("fexit/migrate_misplaced_page")
int BPF_PROG(fexit_migrate_misplaced_page_exit)
{
	return __migrate_misplaced_exit();
}

SEC("fexit/migrate_misplaced_folio")
int BPF_PROG(fexit_migrate_misplaced_folio_exit)
{
	return __migrate_misplaced_exit();
}

SEC("kretprobe/migrate_misplaced_page")
int BPF_KRETPROBE(kretprobe_migrate_misplaced_page_exit)
{
	return __migrate_misplaced_exit();
}

SEC("kretprobe/migrate_misplaced_folio")
int BPF_KRETPROBE(kretprobe_migrate_misplaced_folio_exit)
{
	return __migrate_misplaced_exit();
}

char LICENSE[] SEC("license") = "GPL";
