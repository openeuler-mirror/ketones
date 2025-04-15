// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "runqueue-latency.h"
#include "runqueue-latency.skel.h"
#include "trace_helpers.h"

struct env {
	time_t interval;
	pid_t pid;
	int times;
	bool milliseconds;
	bool per_process;
	bool per_thread;
	bool per_pidns;
	bool timestamp;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "runqueue-latency 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize run queue (scheduler) latency as a histogram.\n"
"\n"
"USAGE: runqlat [--help] [-T] [-m] [--pidnss] [-L] [-P] [-p PID] [interval] [count] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    runqlat         # summarize run queue latency as a histogram\n"
"    runqlat 1 10    # print 1 second summaries, 10 times\n"
"    runqlat -mT 1   # 1s summaries, milliseconds, and timestamps\n"
"    runqlat -P      # show each PID separately\n"
"    runqlat -p 185  # trace PID 185 only\n"
"    runqlat -c CG   # Trace process under cgroupsPath CG\n";

#define OPT_PIDNSS	1 /* --pidnss */

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram", 0 },
	{ "pidnss", OPT_PIDNSS, NULL, 0, "Print a histogram per PID namespace", 0 },
	{ "pids", 'P', NULL, 0, "Print a histogram per process ID", 0 },
	{ "tids", 'L', NULL, 0, "Print a histogram per thread ID", 0 },
	{ "pid", 'p', "PID", 0, "Trace this PID only", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
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
	case 'm':
		env.milliseconds = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'L':
		env.per_thread = true;
		break;
	case 'P':
		env.per_process = true;
		break;
	case OPT_PIDNSS:
		env.per_pidns = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int print_log2_hists(struct bpf_map *hists)
{
	const char *units = env.milliseconds ? "msecs" : "usecs";
	int err, fd = bpf_map__fd(hists);
	__u32 lookup_key = -2, next_key;
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			warning("Failed to lookup list: %d\n", err);
			return -1;
		}
		if (env.per_process)
			printf("\npid = %d %s\n", next_key, hist.comm);
		else if (env.per_thread)
			printf("\ntid = %d %s\n", next_key, hist.comm);
		else if (env.per_pidns)
			printf("\npidns = %u %s\n", next_key, hist.comm);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key = -2;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			warning("Failed to cleanup list : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
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

	struct runqueue_latency_bpf *bpf_obj;
	char ts[32];
	int err;
	int idx, cg_map_fd;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	if ((env.per_thread && (env.per_process || env.per_pidns)) ||
	    (env.per_process && env.per_pidns)) {
		warning("pidnss, pids, tids cann't be used together.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	bpf_obj = runqueue_latency_bpf__open();
	if (!bpf_obj) {
		warning("failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	bpf_obj->rodata->target_per_process = env.per_process;
	bpf_obj->rodata->target_per_thread = env.per_thread;
	bpf_obj->rodata->target_per_pidns = env.per_pidns;
	bpf_obj->rodata->target_ms = env.milliseconds;
	bpf_obj->rodata->target_tgid = env.pid;
	bpf_obj->rodata->filter_memcg = env.cg;

	if (probe_tp_btf("sched_wakeup")) {
		bpf_program__set_autoload(bpf_obj->progs.sched_wakeup_raw, false);
		bpf_program__set_autoload(bpf_obj->progs.sched_wakeup_new_raw, false);
		bpf_program__set_autoload(bpf_obj->progs.sched_switch_raw, false);
	} else {
		bpf_program__set_autoload(bpf_obj->progs.sched_wakeup_btf, false);
		bpf_program__set_autoload(bpf_obj->progs.sched_wakeup_new_btf, false);
		bpf_program__set_autoload(bpf_obj->progs.sched_switch_btf, false);
	}

	err = runqueue_latency_bpf__load(bpf_obj);
	if (err) {
		warning("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* update cgroup path to map */
	if (env.cg) {
		idx = 0;
		cg_map_fd = bpf_map__fd(bpf_obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			warning("Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			warning("Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	err = runqueue_latency_bpf__attach(bpf_obj);
	if (err) {
		warning("Failed to attach BPF programs");
		goto cleanup;
	}

	printf("Tracing run queue lantency... Hit Ctrl-C to end.\n");

	signal(SIGINT, sig_handler);

	/* main loop */
	for (;;) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s\n", ts);
		}

		err = print_log2_hists(bpf_obj->maps.hists);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	runqueue_latency_bpf__destroy(bpf_obj);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
