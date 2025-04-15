// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "exitsnoop.h"
#include "exitsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;
static volatile bool verbose = false;

struct argument {
	char *cgroupspath;
	bool cg;
	bool emit_timestamp;
	pid_t target_pid;
	bool trace_failed_only;
	bool trace_by_process;
};

const char *argp_program_version = "exitsnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace process termination.\n"
"\n"
"USAGE: exitsnoop [-h] [-t] [-x] [-p PID] [-T] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    exitsnoop             # trace process exit events\n"
"    exitsnoop -t          # include timestamps\n"
"    exitsnoop -x          # trace error exits only\n"
"    exitsnoop -p 1216     # only trace PID 1216\n"
"    exitsnoop -T          # trace by thread\n"
"    exitsnoop -c CG       # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "timestamp", 't', NULL, 0, "Include timestamp on output", 0 },
	{ "failed", 'x', NULL, 0, "Trace error exits only", 0 },
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "threadid", 'T', NULL, 0, "Trace by thread", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct argument *argument = state->input;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		verbose = true;
		break;
	case 't':
		argument->emit_timestamp = true;
		break;
	case 'x':
		argument->trace_failed_only = true;
		break;
	case 'T':
		argument->trace_by_process = true;
		break;
	case 'c':
		argument->cgroupspath = arg;
		argument->cg = true;
		break;
	case 'p':
		argument->target_pid = argp_parse_pid(key, arg, state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;
	const struct argument *argument = ctx;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}

	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	if (argument->emit_timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%8s ", ts);
	}

	double age = (e.exit_time - e.start_time) / 1e9;
	printf("%-16s %-7d %-7d %-7d %-7.2f ",
	       e.comm, e.pid, e.ppid, e.tid, age);

	if (!e.sig) {
		if (!e.exit_code)
			printf("0\n");
		else
			printf("code %d\n", e.exit_code);
	} else {
		int sig = e.sig & 0x7f;
		int coredump = e.sig & 0x80;

		if (sig)
			printf("signal %d (%s)", sig, strsignal(sig));
		if (coredump)
			printf(", core dumped");
		printf("\n");
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct argument argument = {
		.trace_by_process = true,
	};
	struct perf_buffer *pb = NULL;
	struct exitsnoop_bpf *obj;
	int err;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, &argument);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = exitsnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = argument.target_pid;
	obj->rodata->trace_failed_only = argument.trace_failed_only;
	obj->rodata->trace_by_process = argument.trace_by_process;
	obj->rodata->filter_cg = argument.cg;

	err = exitsnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* update cgroup path fd to map */
	if (argument.cg) {
		int idx = 0;
		int cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);

		cgfd = open(argument.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			warning("Failed opening cgroup path: %s", argument.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			warning("Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	err = exitsnoop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, &argument, NULL);
	if (!pb) {
		err = -errno;
		warning("Failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (argument.emit_timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-16s %-7s %-7s %-7s %-7s %-s\n",
	       "PCOMM", "PID", "PPID", "TID", "AGE(s)", "EXIT_CODE");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	exitsnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
