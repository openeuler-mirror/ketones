// SPDX-License-Identifier: GPL-2.0

#include "commons.h"
#include "dddos.h"
#include "dddos.skel.h"
#include "btf_helpers.h"
#include "compat.h"
#include <sys/time.h>

static volatile sig_atomic_t exiting;
static bool verbose;

const char *argp_program_version = "dddos 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"This tracks ip_rcv function (using kprobe) and elapsed time\n"
"between received packets to detect potential DDOS attacks.\n"
"\n"
"USAGE: dddos\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		verbose = true;
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event e = {};
	struct timeval tv;

	if (data_sz < sizeof(struct event)) {
		warning("Packet too small\n");
		return 0;
	}

	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	gettimeofday(&tv, NULL);
	double seconds = tv.tv_sec + tv.tv_usec / 1e6;
	long int_part = (long)seconds;
	int micro_part = (int)((seconds - int_part) * 1e6);
	char time_str[20];

	strftime(time_str, sizeof(time_str), "[%D %T.", localtime(&tv.tv_sec));
	printf("%-s%06d]", time_str, micro_part);

	printf(" DDOS Attack => number of packets up to now : %lld\n", e.nb_ddos_packets);

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

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct dddos_bpf *obj;
	struct bpf_buffer *buffer = NULL;
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

	obj = dddos_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		err = 1;
		goto cleanup;
	}

	buffer = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buffer) {
		warning("Failed to create ring/perf buffer: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	err = dddos_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = dddos_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	err = bpf_buffer__open(buffer, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	printf("%-19s %10s\n", "TIME(s)", "MESSAGE");

	while (!exiting) {
		err = bpf_buffer__poll(buffer, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %d\n", err);
			goto cleanup;
		}
	}

cleanup:
	bpf_buffer__free(buffer);
	dddos_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
