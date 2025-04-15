// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "runqslower.h"
#include "runqslower.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting = 0;

struct env {
	pid_t pid;
	pid_t tid;
	__u64 min_us;
	bool previous;
	bool verbose;
} env = {
	.min_us = 1000,
};

const char *argp_program_version = "runqslower 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace high run queue latency.\n"
"\n"
"USAGE: runqslower [--help] [-p PID] [-t tid] [-P] [min_us]\n"
"\n"
"EXAMPLES:\n"
"  runqslower         # trace latency higher than 10000 us (default)\n"
"  runqslower 1000    # trace latency higher than 1000 us\n"
"  runqslower -p 123  # trace pid 123 only\n"
"  runqslower -t 123  # trace tid 123 (use for threads only)\n"
"  runqslower -P      # also show previous task name and TID\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "tid", 't', "TID", 0, "Thread ID to trace", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "previous", 'P', NULL, 0, "also show previous task name and TID", 0 },
	{ "NULL", 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_args(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int pid;
	long long min_us;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'P':
		env.previous = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warning("Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		env.tid = pid;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		min_us = strtoll(arg, NULL, 10);
		if (errno || min_us <= 0) {
			warning("Invalid delay (in us): %s\n", arg);
			argp_usage(state);
		}
		env.min_us = min_us;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct runq_event e;
	char ts[32];

	if (data_sz < sizeof(e)) {
		warning("Packet too small\n");
		return;
	}

	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	strftime_now(ts, sizeof(ts), "%H:%M:%S");
	if (env.previous)
		printf("%-8s %-16s %-7d %-14llu %-16s %-7d\n", ts, e.task, e.pid, e.delta_us, e.prev_task, e.prev_pid);
	else
		printf("%-8s %-16s %-7d %-14llu\n", ts, e.task, e.pid, e.delta_us);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_args,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct runqslower_bpf *bpf_obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	bpf_obj = runqslower_bpf__open();
	if (!bpf_obj) {
		warning("failed to open and/or load BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	bpf_obj->rodata->target_pid = env.pid;
	bpf_obj->rodata->target_tgid = env.tid;
	bpf_obj->rodata->min_us = env.min_us;

	if (probe_tp_btf("sched_wakeup")) {
		bpf_program__set_autoload(bpf_obj->progs.handle_sched_wakeup, false);
		bpf_program__set_autoload(bpf_obj->progs.handle_sched_wakeup_new, false);
		bpf_program__set_autoload(bpf_obj->progs.handle_sched_switch, false);
	} else {
		bpf_program__set_autoload(bpf_obj->progs.sched_wakeup, false);
		bpf_program__set_autoload(bpf_obj->progs.sched_wakeup_new, false);
		bpf_program__set_autoload(bpf_obj->progs.sched_switch, false);
	}

	err = runqslower_bpf__load(bpf_obj);
	if (err) {
		warning("failed to load BPF object: %d", err);
		goto cleanup;
	}

	err = runqslower_bpf__attach(bpf_obj);
	if (err) {
		warning("failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing run queue latency higher than %llu us\n", env.min_us);
	if (env.previous)
		printf("%-8s %-16s %-7s %-14s %-16s %-7s\n", "TIME", "COMM", "TID", "LAT(us)", "PREV-COMM", "PREV-TID");
	else
		printf("%-8s %-16s %-7s %-14s\n", "TIME", "COMM", "PID", "LAT(us)");

	pb = perf_buffer__new(bpf_map__fd(bpf_obj->maps.events), 64,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warning("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warning("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			warning("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	runqslower_bpf__destroy(bpf_obj);

	return err != 0;
}
