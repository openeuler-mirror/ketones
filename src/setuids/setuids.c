// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "setuids.h"
#include "setuids.skel.h"
#include "compat.h"

static volatile sig_atomic_t exiting;

static struct env {
	bool verbose;
	bool timestamp;
} env;

const char *argp_program_version = "setuids 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace the setuid syscalls: privilege escalation.\n"
"\n"
"USAGS:    setuids [-v] [-T]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
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

static void sig_handler(int sig)
{
	exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	if (env.timestamp) {
		char ts[16];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%-8s ", ts);
	}

	printf("%-7d %-16s %-6d ", e->pid, e->comm, e->uid);

	switch (e->type) {
	case UID:
		printf("%-9s uid=%d (%d)\n", "setuid", e->setuid, e->ret);
		break;
	case FSUID:
		printf("%-9s uid=%d (prevuid=%d)\n", "setfsuid", e->setuid, e->ret);
		break;
	case REUID:
		printf("%-9s ruid=%d euid=%d suid=%d (%d)\n", "setreuid",
		       e->ruid, e->euid, e->suid, e->ret);
		break;
	default:
		break;
	}

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu event on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	struct setuids_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = setuids_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to new ring/perf buffer\n");
		err = 1;
		goto cleanup;
	}

	err = setuids_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = setuids_bpf__attach(obj);
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
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing setuid(2) family syscalls. Hit Ctrl-C to end.\n");
	if (env.timestamp)
		printf("%-8s ", "TIME");
	printf("%-7s %-16s %-6s %-9s %s\n", "PID", "COMM", "UID", "SYSCALL",
	       "ARGS (RET)");

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
	setuids_bpf__destroy(obj);
	bpf_buffer__free(buf);

	return err != 0;
}
