// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "adaptive-readahead.h"
#include "compat.bpf.h"
#include "core_fixes.bpf.h"

static __u64 start_stamp = 0;
static unsigned long seq_read_count = 0;
static unsigned long rand_read_count = 0;
static unsigned int seq_read_mode = 0;

static void sysctl_notify(struct pt_regs *ctx, unsigned int mode)
{
	struct event *event = reserve_buf(sizeof(*event));

	if (!event)
		return;

	event->mode = mode;
	submit_buf(ctx, event, sizeof(*event));
}

static void
readahead_control_count(struct pt_regs *ctx, unsigned long lookahead_size)
{
	__u64 timestamp = bpf_ktime_get_ns();

	/* if timestamp interval over 10s, ignore and update */
	if (timestamp - start_stamp > 10000000000) {
		start_stamp = timestamp;
		seq_read_mode = 2;
		seq_read_count = 0;
		rand_read_count = 0;
		return;
	} else {
		start_stamp = timestamp;
	}

	if (lookahead_size > 8) {
		seq_read_count ++;
	} else {
		rand_read_count++;
	}

	if (seq_read_count < 3 && rand_read_count < 2)
		return;

	if (seq_read_count > rand_read_count) {
		if (seq_read_mode != 1) {
			seq_read_mode = 1;
			sysctl_notify(ctx, seq_read_mode);
		}
	} else {
		if (seq_read_mode != 0) {
			seq_read_mode = 0;
			sysctl_notify(ctx, 0);
		}
	}

	if (seq_read_count > 10000 || rand_read_count > 10000) {
		seq_read_count = seq_read_count >> 1;
		rand_read_count = rand_read_count >> 1;
	}

}

SEC("kprobe/page_cache_ra_unbounded")
int BPF_KPROBE(kprobe_page_cache_ra_unbounded)
{
	unsigned long lookahead_size = (unsigned long)PT_REGS_PARM3_CORE(ctx);
	readahead_control_count(ctx, lookahead_size);
	return 0;
}

SEC("kprobe/__do_page_cache_readahead")
int BPF_KPROBE(kprobe__do_page_cache_readahead)
{
	unsigned long lookahead_size = (unsigned long)PT_REGS_PARM5_CORE(ctx);
	readahead_control_count(ctx, lookahead_size);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
