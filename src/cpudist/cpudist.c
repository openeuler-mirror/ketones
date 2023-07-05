// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include "commons.h"
#include "cpudist.skel.h"
#include "cpudist.h"
#include "trace_helpers.h"

static struct env {
	time_t interval;
	pid_t pid;
	char *cgroupspath;
	bool cg;
	int times;
	bool offcpu;
	bool timestamp;
	bool per_process;
	bool per_thread;
	bool milliseconds;
	bool verbose;
} env = {
	.interval = 999999999,
	.pid = -1,
	.times = 99999999,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "cpudist 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize on-CPU time per task as a histogram.\n"
"\n"
"USAGE: cpudist [--help] [-O] [-T] [-m] [-P] [-L] [-p PID] [interval] [count] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    cpudist              # summarize on-CPU time as a histogram\n"
"    cpudist -O           # summarize off-CPU time as a histogram\n"
"    cpudist -c CG        # Trace process under cgroupsPath CG\n"
"    cpudist 1 10         # print 1 second summaries, 10 times\n"
"    cpudist -mT 1        # 1s summaries, milliseconds, and timestamps\n"
"    cpudist -P           # show each PID separately\n"
"    cpudist -p 185       # trace PID 185 only\n";

static const struct argp_option opts[] = {
	{ "offcpu", 'O', NULL, 0, "Measure off-CPU time" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ "pids", 'P', NULL, 0, "Print a histogram per process ID" },
	{ "tids", 'L', NULL, 0, "Print a histogram per thread ID" },
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
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
	case 'm':
		env.milliseconds = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'O':
		env.offcpu = true;
		break;
	case 'P':
		env.per_process = true;
		break;
	case 'L':
		env.per_thread = true;
		break;
	case 'T':
		env.timestamp = true;
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

static int print_log2_hists(struct bpf_map *hists)
{
	char *units = env.milliseconds ? "msecs" : "usecs";
	__u32 lookup_key = -2, next_key;
	int err, fd = bpf_map__fd(hists);

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		struct hist hist;

		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			warning("Failed to lookup hist: %d\n", err);
			return -1;
		}
		if (env.per_process)
			printf("\npid = %d %s\n\n", next_key, hist.comm);
		else if (env.per_thread)
			printf("\ntid = %d %s\n\n", next_key, hist.comm);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key = -2;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			warning("Failed to cleanup hist: %d\n", err);
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

	struct cpudist_bpf *bpf_obj;
	int pid_max, err, cgfd = -1;

	if (!bpf_is_root())
		return 1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	bpf_obj = cpudist_bpf__open();
	if (!bpf_obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	if (probe_tp_btf("sched_switch"))
		bpf_program__set_autoload(bpf_obj->progs.sched_switch_raw, false);
	else
		bpf_program__set_autoload(bpf_obj->progs.sched_switch_btf, false);

	/* initialize global data (filtering options) */
	bpf_obj->rodata->filter_memcg = env.cg;
	bpf_obj->rodata->target_per_process = env.per_process;
	bpf_obj->rodata->target_per_thread = env.per_thread;
	bpf_obj->rodata->target_ms = env.milliseconds;
	bpf_obj->rodata->target_offcpu = env.offcpu;
	bpf_obj->rodata->target_tgid = env.pid;

	pid_max = get_pid_max();
	if (pid_max < 0) {
		warning("Failed to get pid_max\n");
		return 1;
	}

	bpf_map__set_max_entries(bpf_obj->maps.start, pid_max);
	if (!env.per_process && !env.per_thread)
		bpf_map__set_max_entries(bpf_obj->maps.hists, 1);
	else
		bpf_map__set_max_entries(bpf_obj->maps.hists, pid_max);


	err = cpudist_bpf__load(bpf_obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* Update cgroup path fd to map */
	if (env.cg) {
		int idx = 0;
		int cg_map_fd = bpf_map__fd(bpf_obj->maps.cgroup_map);

		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			warning("Failed opening Cgroup path: %s\n", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			warning("Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	err = cpudist_bpf__attach(bpf_obj);
	if (err) {
		warning("Failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	printf("Tracing %s-CPU time... Hit Ctrl-C to end.\n", env.offcpu ? "off" : "on");

	/* Main poll */
	for (;;) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			char ts[32];

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
	cpudist_bpf__destroy(bpf_obj);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
