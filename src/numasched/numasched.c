// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include <numa.h>
#include "numasched.skel.h"
#include "numasched.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;

static struct env {
	bool verbose;
	bool timestamp;
	char *comm;
	pid_t pid;
	pid_t tid;
} env = {
	.pid = INVALID_PID,
	.tid = INVALID_PID,
};

const char *argp_program_version = "numasched 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace task NUMA switch\n"
"\n"
"USAGE: numasched [-p PID] [-t TID] [-c COMM]\n"
"\n"
"EXAMPLES:\n"
"    ./numasched             # Trace all numa node switch\n"
"    ./numasched -p 123      # Trace pid 123 only\n"
"    ./numasched -t 1234     # Trace thread id 1234 only\n"
"    ./numasched -c comm     # Trace this comm only\n"
"    ./numasched -T          # Include timestamp\n"
"    ./numasched -v          # Verbose debug output\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "tid", 't', "TID", 0, "Trace this TID only" },
	{ "comm", 'c', "COMM", 0, "Trace this comm only" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		errno = 0;
		env.tid = strtol(arg, NULL, 10);
		if (errno) {
			warning("Invalid tid: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env.comm = arg;
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

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;

	if (env.comm && strstr(e->comm, env.comm) == NULL)
		return;

	if (env.timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");

		printf("%-8s ", ts);
	}

	printf("%-16s %-7d %-7d %8d -> %-8d\n", e->comm, e->pid, e->tid,
	       e->prev_numa_node_id, e->numa_node_id);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on cpu #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	static struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct perf_buffer *pb = NULL;
	struct numasched_bpf *bpf_obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (numa_max_node() == 0) {
		printf("We only have one NUMA Node, so we don't need to track NUMA switching.\n");
		return 0;
	}

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	bpf_obj = numasched_bpf__open();
	if (!bpf_obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	/* Init global data (filtering options) */
	bpf_obj->rodata->target_tgid = env.pid;
	bpf_obj->rodata->target_pid = env.tid;

	if (probe_tp_btf("sched_switch"))
		bpf_program__set_autoload(bpf_obj->progs.sched_switch_raw, false);
	else
		bpf_program__set_autoload(bpf_obj->progs.sched_switch_btf, false);

	err = numasched_bpf__load(bpf_obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = numasched_bpf__attach(bpf_obj);
	if (err) {
		warning("Failed to attach programs: %d\n", err);
		goto cleanup;
	}

	if (env.timestamp)
		printf("%-9s", "TIME");

	printf("%-16s %-7s %-7s %8s    %-8s\n", "COMM", "PID", "TID", "SRC_NID",
		"DST_NID");

	pb = perf_buffer__new(bpf_map__fd(bpf_obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warning("Failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Cann't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* Loop */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}

		/* reset err to retrun 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	numasched_bpf__destroy(bpf_obj);

	return err != 0;
}
