// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>

#include "commons.h"
#include "compat.h"
#include "unlinksnoop.h"
#include "unlinksnoop.skel.h"
#include "btf_helpers.h"

static volatile sig_atomic_t exiting = 0;

static struct {
	int pid;
	bool verbose;
	bool timestamp;
	bool print_ppid;
} env;

const char *argp_program_version = "unlinksnoop 0.1";
const char *argp_protram_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace unlink syscalls\n"
"\n"
"USAGE: unlinksnoop [-h] [-p PID] [-v]\n";

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
		printf("%-20s ", ts);
	}

	if (env.print_ppid)
		printf("%-10d ", e->ppid);

	printf("%-10d %-16s %s\n", e->pid, e->comm, e->filename);

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

static int print_event(struct unlinksnoop_bpf *obj, struct bpf_buffer *buf)
{
	int err = 0;

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		return 1;
	}

	if (env.timestamp)
		printf("%-20s ", "TIMESTAMP");
	if (env.print_ppid)
		printf("%-10s ", "PPID");

	printf("%-10s %-16s %s\n", "PID", "COMM", "FILES");

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
	struct unlinksnoop_bpf *obj;
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

	obj = unlinksnoop_bpf__open_opts(&open_opts);
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

	err = unlinksnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = unlinksnoop_bpf__attach(obj);
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
	unlinksnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
