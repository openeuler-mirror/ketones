// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "statsnoop.h"
#include "statsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"

static volatile sig_atomic_t exiting;

static pid_t target_pid = 0;
static bool trace_failed_only = false;
static bool emit_timestamp = false;
static bool verbose = false;

const char *argp_program_version = "statsnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace stat syscalls.\n"
"\n"
"USAGE: statsnoop [-h] [-t] [-x] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    statsnoop             # trace all stat syscalls\n"
"    statsnoop -t          # include timestamps\n"
"    statsnoop -x          # only show failed stats\n"
"    statsnoop -p 1216     # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "failed", 'x', NULL, 0, "Only show failed stats" },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		target_pid = argp_parse_pid(key, arg, state);
		break;
	case 'x':
		trace_failed_only = true;
		break;
	case 't':
		emit_timestamp = true;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	int fd, err;

	if (e->ret >= 0) {
		fd = e->ret;
		err = 0;
	} else {
		fd = -1;
		err = e->ret;
	}

	if (emit_timestamp)
		printf("%-14.9f ", time_since_start());
	printf("%-7d %-20s %4d %8s %-s\n", e->pid, e->comm, fd, strerrno(err), e->pathname);

	return 0;
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
	struct bpf_buffer *buf = NULL;
	struct statsnoop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
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

	obj = statsnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->trace_failed_only = trace_failed_only;

	if (!tracepoint_exists("syscalls", "sys_enter_statfs")) {
		bpf_program__set_autoload(obj->progs.handle_statfs_entry, false);
		bpf_program__set_autoload(obj->progs.handle_statfs_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_statx")) {
		bpf_program__set_autoload(obj->progs.handle_statx_entry, false);
		bpf_program__set_autoload(obj->progs.handle_statx_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_newstat")) {
		bpf_program__set_autoload(obj->progs.handle_newstat_entry, false);
		bpf_program__set_autoload(obj->progs.handle_newstat_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_newfstatat")) {
		bpf_program__set_autoload(obj->progs.handle_newfstatat_entry, false);
		bpf_program__set_autoload(obj->progs.handle_newfstatat_return, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_newlstat")) {
		bpf_program__set_autoload(obj->progs.handle_newlstat_entry, false);
		bpf_program__set_autoload(obj->progs.handle_newlstat_return, false);
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		warning("Failed to create ring/perf buffer\n");
		goto cleanup;
	}

	err = statsnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = statsnoop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n",  err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (emit_timestamp)
		printf("%-14s ", "TIME(s)");
	printf("%-7s %-20s %4s %8s %-s\n", "PID", "COMM", "RET", "ERR", "PATH");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* retset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	statsnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
