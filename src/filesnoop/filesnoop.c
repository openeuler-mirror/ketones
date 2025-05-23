// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>

#include "commons.h"
#include "compat.h"
#include "filesnoop.h"
#include "filesnoop.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;

static struct env {
	bool verbose;
	bool timestamp;
	const char *filename;
	bool filter_filename;
	bool print_ppid;
	enum file_op target_op;
} env;

const char *argp_program_version = "filesnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Tracking the operational of a specific file.\n"
"\n"
"USAGE: filesnoop [-v] [-T] [-P] [-f filename] [-o OPEN]\n"
"\n"
"EXAMPLE:\n"
"    filesnoop -o READ        # trace read/readv syscall\n"
"                             # (write,read,close)\n";

static const struct argp_option opts[] = {
	{ "version", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "filename", 'f', "FILENAME", 0, "Trace FILENAME only", 0 },
	{ "operation", 'o', "OPERATION", 0, "Trace OPERATION only", 0 },
	{ "print-ppid", 'P', NULL, 0, "Trace parent pid", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

const char *op2string[] = {
	[F_NONE] = "NONE",
	[F_WRITE] = "WRITE",
	[F_WRITEV] = "WRITEV",
	[F_READ] = "READ",
	[F_READV] = "READV",
	[F_RENAMEAT] = "RENAMEAT",
	[F_RENAMEAT2] = "RENAMEAT2",
	[F_UNLINKAT] = "UNLINKAT",
	[F_CLOSE] = "CLOSE",
	[F_UTIMENSAT] = "UTIMENSAT",
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
	case 'T':
		env.timestamp = true;
		break;
	case 'f':
		env.filename = arg;
		env.filter_filename = true;
		break;
	case 'P':
		env.print_ppid = true;
		break;
	case 'o':
		if (env.target_op != F_NONE)
			break;
		for (int i = 0; i < ARRAY_SIZE(op2string); i++) {
			if (op2string[i] && strcmp(op2string[i], arg) == 0) {
				env.target_op = i;
			}
		}
		if (env.target_op == F_NONE) {
			warning("%s is not valid operation\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static void sig_handler(int sig)
{
	exiting = 1;
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
	const struct event *e = data;
	int fd = e->fd;

	if (env.timestamp) {
		char ts[16];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%-9s ", ts);
	}

	if (env.print_ppid)
		printf("%-7d ", e->ppid);

	printf("%-7d %-16s %-10s %5d %5d %s\n", e->pid, e->comm, op2string[e->op],
	       fd, e->ret, e->filename);
	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void alias_parse(char *prog)
{
	char *name = basename(prog);

	if (!strcmp(name, "closesnoop"))
		env.target_op = F_CLOSE;
	else if (!strcmp(name, "writesnoop"))
		env.target_op = F_WRITE;
	else if (!strcmp(name, "readsnoop"))
		env.target_op = F_READ;
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	DEFINE_SKEL_OBJECT(obj);
	int err;

	alias_parse(argv[0]);
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.target_op == F_NONE) {
		warning("Not set target operation\n");
		return -1;
	}

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = SKEL_OPEN();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer");
		err = 1;
		goto cleanup;
	}

	if (env.filter_filename) {
		obj->rodata->target_filename_sz = strlen(env.filename);
		obj->rodata->filter_filename = env.filter_filename;
		strcpy(obj->bss->target_filename, env.filename);
	}
	obj->rodata->target_op = env.target_op;

	if (!tracepoint_exists("syscalls", "sys_enter_open")) {
		bpf_program__set_autoload(obj->progs.tracepoint_sys_enter_open, false);
		bpf_program__set_autoload(obj->progs.tracepoint_sys_exit_open, false);
	}

	if (!tracepoint_exists("syscalls", "sys_enter_openat2")) {
		bpf_program__set_autoload(obj->progs.tracepoint_sys_enter_openat2, false);
		bpf_program__set_autoload(obj->progs.tracepoint_sys_exit_openat2, false);
	}

	err = SKEL_LOAD(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = SKEL_ATTACH(obj);
	if (err) {
		warning("Failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(-errno));
		err = 1;
		goto cleanup;
	}

	if (env.timestamp)
		printf("%-9s ", "TIME");
	if (env.print_ppid)
		printf("%-7s ", "PPID");
	printf("%-7s %-16s %-10s %5s %5s %s\n", "PID", "COMM", "OPERATION", "FD",
	       "RET", "FILENAME");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %d\n", err);
			goto cleanup;
		}
		/* reset err to 0 when exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	SKEL_DESTROY(obj);

	return err != 0;
}
