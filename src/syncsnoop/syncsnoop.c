// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "syncsnoop.h"
#include "syncsnoop.skel.h"
#include "compat.h"

static volatile sig_atomic_t exiting;
static bool verbose = false;

const char *argp_program_version = "syncsnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace sync() variety of syscalls.\n"
"\n"
"USAGE:  syncsnoop [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

static const char *funcnames[SYS_T_MAX] = {
	[SYS_T_MIN]		= "N/A",
	[SYS_SYNC]		= "sync",
	[SYS_FSYNC]		= "fsync",
	[SYS_FDATASYNC]		= "fdatasync",
	[SYS_MSYNC]		= "msync",
	[SYS_SYNC_FILE_RANGE]	= "sync_file_range",
	[SYS_SYNCFS]		= "syncfs",
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
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

	printf("%-18.9f %-*d %-16s %s\n", (float)e->ts_us / 1000000, get_pid_maxlen(),
	       e->pid, e->comm, funcnames[e->sys]);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
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

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

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
		warning("Failed to create ring/perf buffer: %d\n", err);
		err = 1;
		goto cleanup;
	}

	err = SKEL_LOAD(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = SKEL_ATTACH(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal hander: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing sync syscalls... Hit Ctrl-C to end.\n");
	printf("%-18s %-*s %-16s %s\n", "TIME(s)", get_pid_maxlen(), "PID", "COMM", "CALL");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Failed to polling ring/perf buffer: %d\n", err);
			break;
		}
		/* reset err to 0 when exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	SKEL_DESTROY(obj);

	return err != 0;
}
