// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bashreadline.h"

#define TASK_COMM_LEN	16
#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(*(x)))

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("uretprobe/readline")
int BPF_URETPROBE(printret, const void *ret)
{
	readline_str_t data;
	char comm[TASK_COMM_LEN];
	char bashname[] = { 'b', 'a', 's', 'h', 0 };
	u32 pid;

	if (!ret)
		return 0;

	bpf_get_current_comm(&comm, sizeof(comm));
	for (int i = 0; i < ARRAY_SIZE(bashname); i++) {
		if (bashname[i] != comm[i])
			return 0;
	}

	pid = bpf_get_current_pid_tgid() >> 32;
	data.pid = pid;
	bpf_core_read_user_str(&data.str, sizeof(data.str), ret);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
