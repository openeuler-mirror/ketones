// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include <linux/perf_event.h>
#include "runqlen.h"
#include "runqlen.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include <sys/syscall.h>

struct env {
	bool per_cpu;
	bool runqocc;
	bool timestamp;
	bool host;
	time_t interval;
	int freq;
	int times;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
	.freq = 99,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "runqlen 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize scheduler run queue length as a histogram.\n"
"\n"
"USAGE: runqlen [--help] [-C] [-O] [-T] [-f FREQUENCY] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    runqlen         # summarize run queue length as a histogram\n"
"    runqlen 1 10    # print 1 second summaries, 10 times\n"
"    runqlen -T 1    # 1s summaries and timestamps\n"
"    runqlen -O      # report run queue occupancy\n"
"    runqlen -C      # show each CPU separately\n"
"    runqlen -H      # show nr_running from host's rq instead of cfs_rq\n"
"    runqlen -f 199  # sample at 199HZ\n";

static const struct argp_option opts[] = {
	{ "cpus", 'C', NULL, 0, "Print output for each cpu separately" },
	{ "frequency", 'f', "FREQUENCY", 0, "Sample with a certain frequency" },
	{ "runqocc", 'O', NULL, 0, "Report run queue occupancy" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "verbose", 'v', NULL, 0, "Verbose output debug" },
	{ "host", 'H', NULL, 0, "Report nr_running from host's rq" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
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
	case 'C':
		env.per_cpu = true;
		break;
	case 'O':
		env.runqocc = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'H':
		env.host = true;
		break;
	case 'f':
		errno = 0;
		env.freq = strtol(arg, NULL, 10);
		if (errno) {
			warning("Invalid freq (in hz): %s\n", arg);
			argp_usage(state);
		}
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
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				      struct bpf_link *links[])
{
	for (int i = 0; i < nr_cpus; i++) {
		struct perf_event_attr attr = {
			.type = PERF_TYPE_SOFTWARE,
			.freq = 1,
			.sample_period = freq,
			.config = PERF_COUNT_SW_CPU_CLOCK,
		};

		int fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);

		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;

			warning("Failed to init perf sampling: %s\n", strerror(errno));
			return -1;
		}

		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			warning("Failed to attach perf event on cpu#%d!\n", i);
			close(fd);
			return -1;
		}
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

static struct hist zero;

static void print_runq_occupancy(struct runqlen_bpf__bss *bss)
{
	int i = 0;

	do {
		__u64 samples, idle = 0, queued = 0;
		float runqocc;
		struct hist hist;

		hist = bss->hists[i];
		bss->hists[i] = zero;

		for (int slot = 0; slot < MAX_SLOTS; slot++) {
			__u64 val = hist.slots[slot];

			if (slot == 0)
				idle += val;
			else
				queued += val;
		}

		samples = idle + queued;
		runqocc = queued * 1.0 / max(1ULL, samples);
		if (env.per_cpu)
			printf("runqocc, CPU#%d: %6.2f%%\n", i, 100 * runqocc);
		else
			printf("runqocc: %0.2f%%\n", 100 * runqocc);
	} while (env.per_cpu && ++i < nr_cpus);
}

static void print_linear_hists(struct runqlen_bpf__bss *bss)
{
	struct hist hist;
	int i = 0;

	do {
		hist = bss->hists[i];
		bss->hists[i] = zero;
		if (env.per_cpu)
			printf("cpu = %d\n", i);

		print_linear_hist(hist.slots, MAX_SLOTS, 0, 1, "runqlen");
	} while (env.per_cpu && ++i < nr_cpus);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct bpf_link *links[MAX_CPU_NR] = {};
	struct runqlen_bpf *bpf_obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		warning("Failed to get # of possible cpus: '%s'!\n",
			strerror(-nr_cpus));
		return 1;
	}

	if (nr_cpus > MAX_CPU_NR) {
		warning("The number of cpu cores is too big, please increase "
			"MAX_CPU_NR's value and recompile");
		return 1;
	}

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return 1;
	}

	bpf_obj = runqlen_bpf__open_opts(&open_opts);
	if (!bpf_obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	/* Init global data (filtering options) */
	bpf_obj->rodata->target_per_cpu = env.per_cpu;
	bpf_obj->rodata->target_host = env.host;

	err = runqlen_bpf__load(bpf_obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (!bpf_obj->bss) {
		warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = open_and_attach_perf_event(env.freq, bpf_obj->progs.do_sample, links);
	if (err)
		goto cleanup;

	printf("Sampling run queue length... Hit Ctrl-C to end.\n");

	signal(SIGINT, sig_handler);

	for (;;) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			char ts[32];

			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s\n", ts);
		}

		if (env.runqocc)
			print_runq_occupancy(bpf_obj->bss);
		else
			print_linear_hists(bpf_obj->bss);

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	for (int i = 0; i < nr_cpus; i++)
		bpf_link__destroy(links[i]);

	runqlen_bpf__destroy(bpf_obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
