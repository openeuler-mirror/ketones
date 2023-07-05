// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "capable.h"

#define MAX_ENTRIES	10240

extern int LINUX_KERNEL_VERSION	__kconfig;

struct myinfo myinfo = {};

const volatile enum uniqueness unique_type = UNQ_OFF;
const volatile bool kernel_stack = false;
const volatile bool user_stack = false;
const volatile bool filter_cg = false;
const volatile pid_t target_pid = -1;

struct args_t {
	int cap;
	int cap_out;
};

struct unique_key {
	int cap;
	u32 tgid;
	u64 cgroupid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct args_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, struct cap_event);
} info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct unique_key);
	__type(value, u64);
} seen SEC(".maps");

SEC("kprobe/cap_capable")
int BPF_KPROBE(kprobe__cap_capable_entry, const struct cred *cred,
	       struct user_namespace *target_ns, int cap, int cap_out)
{
	__u64 pid_tgid;
	struct bpf_pidns_info nsdata;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;


	if (bpf_get_ns_current_pid_tgid(myinfo.dev, myinfo.ino, &nsdata,
					sizeof(struct bpf_pidns_info)))
		return 0;

	pid_tgid = (__u64)nsdata.tgid << 32 | nsdata.pid;
	if (myinfo.pid_tgid == pid_tgid)
		return 0;

	if (target_pid != -1 && target_pid != nsdata.tgid)
		return 0;

	struct args_t args = {};
	args.cap = cap;
	args.cap_out = cap_out;

	bpf_map_update_elem(&start, &pid_tgid, &args, BPF_ANY);

	return 0;
}

SEC("kretprobe/cap_capable")
int BPF_KRETPROBE(kretprobe__cap_capable_exit)
{
	__u64 pid_tgid;
	struct args_t *argsp;
	struct key_t i_key;
	struct bpf_pidns_info nsdata;

	if (bpf_get_ns_current_pid_tgid(myinfo.dev, myinfo.ino, &nsdata,
					sizeof(struct bpf_pidns_info)))
		return 0;

	pid_tgid = (__u64)nsdata.tgid << 32 | nsdata.pid;
	argsp = bpf_map_lookup_elem(&start, &pid_tgid);
	if (!argsp)
		return 0;

	bpf_map_delete_elem(&start, &pid_tgid);

	struct cap_event event = {};
	event.pid = pid_tgid >> 32;
	event.tgid = pid_tgid;
	event.cap = argsp->cap;
	event.uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&event.task, sizeof(event.task));
	event.ret = PT_REGS_RC(ctx);

	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 1, 0)) {
		/* @opts: bitmask of options defined in include/linux/security.h */
		event.audit = (argsp->cap_out & 0b10) == 0;
		event.insetid = (argsp->cap_out & 0b100) != 0;
	} else {
		event.audit = argsp->cap_out;
		event.insetid = -1;
	}

	if (unique_type) {
		struct unique_key key = { .cap = argsp->cap };

		if (unique_type == UNQ_CGROUP)
			key.cgroupid = bpf_get_current_cgroup_id();
		else
			key.tgid = pid_tgid;

		if (bpf_map_lookup_elem(&seen, &key))
			return 0;

		u64 zero = 0;
		bpf_map_update_elem(&seen, &key, &zero, BPF_ANY);
	}

	if (kernel_stack || user_stack) {
		i_key.pid = pid_tgid >> 32;
		i_key.tgid = pid_tgid;

		i_key.kernel_stack_id = i_key.user_stack_id = -1;
		if (user_stack)
			i_key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
		if (kernel_stack)
			i_key.kernel_stack_id = bpf_get_stackid(ctx, &stackmap, 0);

		bpf_map_update_elem(&info, &i_key, &event, BPF_NOEXIST);
	}
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
