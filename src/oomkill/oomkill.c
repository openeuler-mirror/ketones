// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "oomkill.h"
#include "oomkill.skel.h"
#include "compat.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;
static bool verbose = false;

const char *argp_program_version = "oomkill 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace OOM kills.\n"
"\n"
"USAGE: oomkill [-h]\n"
"\n"
"EXAMPLES:\n"
"    oomkill               # trace OOM kills\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
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

static int handle_event(void *ctx, void *data, size_t len)
{
	FILE *f;
	char buf[256];
	int n = 0;
	char ts[32];
	struct data_t *e = data;

	f = fopen("/proc/loadavg", "r");
	if (f) {
		memset(buf, 0, sizeof(buf));
		n = fread(buf, 1, sizeof(buf), f);
		fclose(f);
	}
	strftime_now(ts, sizeof(ts), "%H:%M:%S");

	printf("%s Trigger by PID %d (\"%s\"), OOM kill of PID %d (\"%s\"), %lld pages",
	       ts, e->fpid, e->fcomm, e->tpid, e->tcomm, e->pages);
	if (n)
		printf(", loadavg: %s", buf);
	else
		printf("\n");

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

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

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	struct oomkill_bpf *obj;
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

	obj = oomkill_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		warning("Failed to create ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	err = oomkill_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = oomkill_bpf__attach(obj);
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
		warning("Can't set signal handler: %d\n", err);
		err = 1;
		goto cleanup;
	}

	printf("Tracing OOM kill... Ctrl-C to stop.\n");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("error polling ring/perf buffer: %d\n", err);
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	oomkill_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
