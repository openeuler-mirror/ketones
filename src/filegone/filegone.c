// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on filegone.py - Curu Wong

#include "commons.h"
#include "compat.h"
#include "filegone.h"
#include "filegone.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting = 0;

static struct {
	int pid;
	bool verbose;
	bool timestamp;
	bool print_ppid;
} env;

const char *argp_program_version = "filegone 0.1";
const char *argp_protram_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace why file gone (deleted or renamed).\n"
"\n"
"USAGE: filegone [-h] [-p PID] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "pid", 'p', "PID", 0, "Trace PID only" },
	{ "print-ppid", 'P', NULL, 0, "Print parent pid" },
	{ "timestamp", 'T', NULL, 0, "Print timestamp" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'p':
		env.pid = argp_parse_long(key, arg, state);
		break;
	case 'P':
		env.print_ppid = true;
		break;
	case 'T':
		env.timestamp = true;
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;

	if (env.timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "[%m/%d/%y %H:%M:%S]");
		printf("%-19s ", ts);
	}

	if (env.print_ppid)
		printf("%-7d ", e->ppid);

	printf("%-7d %-16s %10.10s %6s %s", e->pid, e->comm, strerrno(e->ret),
	       e->action == 'D' ? "DELETE" : "RENAME", e->fname);
	if (e->action == 'R')
		printf(" > %s", e->fname2);
	printf("\n");

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu event on CPU #%d!\n", lost_cnt, cpu);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int print_event(struct filegone_bpf *obj, struct bpf_buffer *buf)
{
	int err = 0;

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		return 1;
	}

	if (env.timestamp)
		printf("%-19s ", "TIMESTAMP");
	if (env.print_ppid)
		printf("%-7s ", "PPID");

	printf("%-7s %-16s %10s %s\n", "PID", "COMM", "RET", "FILES");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %d\n", err);
			return 1;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	const struct argp argp = {
		.parser = parse_arg,
		.options = opts,
		.doc = argp_program_doc,
	};
	struct filegone_bpf *obj;
	struct bpf_buffer *buf = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = filegone_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	obj->rodata->target_pid = env.pid;

	if (!tracepoint_exists("syscalls", "sys_enter_unlink")) {
		bpf_program__set_autoload(obj->progs.tracepoint_enter_unlink, false);
		bpf_program__set_autoload(obj->progs.tracepoint_exit_unlink, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_unlinkat")) {
		bpf_program__set_autoload(obj->progs.tracepoint_enter_unlinkat, false);
		bpf_program__set_autoload(obj->progs.tracepoint_exit_unlinkat, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_rename")) {
		bpf_program__set_autoload(obj->progs.tracepoint_enter_rename, false);
		bpf_program__set_autoload(obj->progs.tracepoint_exit_rename, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_renameat")) {
		bpf_program__set_autoload(obj->progs.tracepoint_enter_renameat, false);
		bpf_program__set_autoload(obj->progs.tracepoint_exit_renameat, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_renameat2")) {
		bpf_program__set_autoload(obj->progs.tracepoint_enter_renameat2, false);
		bpf_program__set_autoload(obj->progs.tracepoint_exit_renameat2, false);
	}
	if (!tracepoint_exists("syscalls", "sys_enter_rmdir")) {
		bpf_program__set_autoload(obj->progs.tracepoint_enter_rmdir, false);
		bpf_program__set_autoload(obj->progs.tracepoint_exit_rmdir, false);
	}

	err = filegone_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = filegone_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	err = print_event(obj, buf);
	if (err)
		goto cleanup;

cleanup:
	bpf_buffer__free(buf);
	filegone_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
