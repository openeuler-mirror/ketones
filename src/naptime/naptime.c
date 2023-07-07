// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "naptime.h"
#include "naptime.skel.h"
#include "btf_helpers.h"
#include "compat.h"

static volatile sig_atomic_t exiting;
static bool verbose = false;
static bool timestamp = false;

const char *argp_program_version = "naptime 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Show voluntary sleep calls.\n"
"\n"
"USAGE:    naptime [-v] [-T]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ NULL, 'h', NULL, 0, "Show the full help" },
	{}
};

static void sig_handler(int sig)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'T':
		timestamp = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	if (timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%-8s ", ts);
	}

	printf("%-6d %-16s %-6d %-16s %lld.%03lld\n",
	       e->ppid, e->pcomm, e->pid, e->comm, e->tv_sec, e->tv_nsec / 1000000);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu event on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct naptime_bpf *obj;
	struct bpf_buffer *buf = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);

	obj = naptime_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer\n");
		err = 1;
		goto cleanup;
	}

	err = naptime_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = naptime_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	printf("Tracing sleeps. Hit Ctrl-C to end.\n");

	if (timestamp)
		printf("%-8s ", "TIME");
	printf("%-6s %-16s %-6s %-16s %s\n",
	       "PPID", "PCOMM", "PID", "COMM", "SECONDS");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %d\n", err);
			break;
		}
		/* reset err to 0 when exiting */
		err = 0;
	}

cleanup:
	naptime_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
