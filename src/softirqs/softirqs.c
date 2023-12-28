// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "softirqs.h"
#include "softirqs.skel.h"
#include "trace_helpers.h"

struct env {
	bool distributed;
	bool nanoseconds;
	bool count;
	time_t interval;
	int times;
	bool timestamp;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
	.count = false,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "softirqs 0.1";
const char *argp_program_buf_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize soft irq event time as histograms.\n"
"\n"
"USAGE: softirqs [--help] [-T] [-N] [-d] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"  softirqs           # sum soft irq event time\n"
"  softirqs -d        # show soft irq event time as histograms\n"
"  softirqs 1 10      # print 1 second summaries, 10 times\n"
"  softirqs -NT 1     # 1s summaries, nanoseconds, and timestamps\n";

static const struct argp_option opts[] = {
	{ "distributed", 'd', NULL, 0, "Show distributions as histograms" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "nanoseconds", 'N', NULL, 0, "Output in nanoseconds" },
	{ "count", 'C', NULL, 0, "Show event counts with timing" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		env.distributed = true;
		break;
	case 'N':
		env.nanoseconds = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'C':
		env.count = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				warning("Invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 10);
			if (errno) {
				warning("Invalid times\n");
				argp_usage(state);
			}
		} else {
			warning("Unrecongnized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

enum {
	HI_SOFTIRQ,
	TIMER_SOFTIRQ,
	NET_TX_SOFTIRQ,
	NET_RX_SOFTIRQ,
	BLOCK_SOFTIRQ,
	IRQ_POLL_SOFTIRQ,
	TASKLET_SOFTIRQ,
	SCHED_SOFTIRQ,
	HRTIMER_SOFTIRQ,
	RCU_SOFTIRQ,
	NR_SOFTIRQS
};

static char *softirq_vec_names[] = {
	[HI_SOFTIRQ] = "hi",
	[TIMER_SOFTIRQ] = "timer",
	[NET_TX_SOFTIRQ] = "net_tx",
	[NET_RX_SOFTIRQ] = "net_rx",
	[BLOCK_SOFTIRQ] = "block",
	[IRQ_POLL_SOFTIRQ] = "irq_poll",
	[TASKLET_SOFTIRQ] = "tasklet",
	[SCHED_SOFTIRQ] = "sched",
	[HRTIMER_SOFTIRQ] = "hrtimer",
	[RCU_SOFTIRQ] = "rcu"
};

static int print_count(struct softirqs_bpf__bss *bss)
{
	const char *units = env.nanoseconds ? "nsecs" : "usecs";
	__u64 count, time;
	__u32 vec;

	printf("%-16s %-6s%-5s  %-11s\n", "SOFTIRQ", "TOTAL_",
			units, env.count ? "TOTAL_count" : "");

	for (vec = 0; vec < NR_SOFTIRQS; vec++) {
		time = __atomic_exchange_n(&bss->time[vec], 0,
					   __ATOMIC_RELAXED);
		count = __atomic_exchange_n(&bss->counts[vec], 0,
					    __ATOMIC_RELAXED);

		if (count > 0) {
			printf("%-16s %11llu", softirq_vec_names[vec], time);
			if (env.count)
				printf("  %11llu", count);
			printf("\n");
		}
	}

	return 0;
}

static struct hist zero;
static int print_hist(struct softirqs_bpf__bss *bss)
{
	const char *units = env.nanoseconds ? "nsecs" : "usecs";
	__u32 vec;

	for (vec = 0; vec < NR_SOFTIRQS; vec++) {
		struct hist hist = bss->hists[vec];

		bss->hists[vec] = zero;
		if (!memcmp(&zero, &hist, sizeof(hist)))
			continue;

		printf("softirq = %s\n", softirq_vec_names[vec]);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		printf("\n");
	}

	return 0;
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct softirqs_bpf *bpf_obj;
	char ts[32];
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	bpf_obj = softirqs_bpf__open();
	if (!bpf_obj) {
		warning("failed to open BPF object\n");
		return 1;
	}

	if (probe_tp_btf("softirq_entry")) {
		bpf_program__set_autoload(bpf_obj->progs.softirq_entry_raw, false);
		bpf_program__set_autoload(bpf_obj->progs.softirq_exit_raw, false);
	} else {
		bpf_program__set_autoload(bpf_obj->progs.softirq_entry_btf, false);
		bpf_program__set_autoload(bpf_obj->progs.softirq_exit_btf, false);
	}

	/* initialize global data (filtering options) */
	bpf_obj->rodata->target_dist = env.distributed;
	bpf_obj->rodata->target_ns = env.nanoseconds;

	err = softirqs_bpf__load(bpf_obj);
	if (err) {
		warning("failed to load BPF objects: %d\n", err);
		goto cleanup;
	}

	if (!bpf_obj->bss) {
		warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = softirqs_bpf__attach(bpf_obj);
	if (err) {
		warning("failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing softirq event time... Hit Ctrl-C to end.\n");

	for (;;) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s\n", ts);
		}

		if (!env.distributed)
			err = print_count(bpf_obj->bss);
		else
			err = print_hist(bpf_obj->bss);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	softirqs_bpf__destroy(bpf_obj);

	return err != 0;
}

