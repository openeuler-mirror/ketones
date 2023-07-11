// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "oomkill.h"
#include "compat.bpf.h"

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
	struct data_t *data;

	data = reserve_buf(sizeof(*data));
	if (!data)
		return 0;

	data->fpid = bpf_get_current_pid_tgid() >> 32;
	data->tpid = BPF_CORE_READ(oc, chosen, tgid);
	data->pages = BPF_CORE_READ(oc, totalpages);
	bpf_get_current_comm(&data->fcomm, sizeof(data->fcomm));
	BPF_CORE_READ_STR_INTO(&data->tcomm, oc, chosen, comm);

	submit_buf(ctx, data, sizeof(*data));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
