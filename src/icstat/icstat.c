// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on icstat.bt - Brendan Gregg

#include "commons.h"
#include "icstat.h"
#include "icstat.skel.h"
#include "btf_helpers.h"

static volatile sig_atomic_t exiting;
static struct {
	bool verbose;
	bool interval;
	bool timestamp;
} env = {
	.interval = 1,
};

const char *argp_program_version = "icstat 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Inode cache hit statistics."
"\n"
"USAGE: icstat [-h] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "interval", 'i', "INTERVAL", 0, "Summary interval in seconds", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
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
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
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

static void print_map(struct icstat_bpf *obj)
{
	int zero = 0;
	int fd = bpf_map__fd(obj->maps.counts);
	struct info info;

	if (env.timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%8s ", ts);
	}

	if (bpf_map_lookup_elem(fd, &zero, &info)) {
		printf("%10d %10d %6.2f%%\n", 0, 0, 0.00);
		return;
	}

	printf("%10lld %10lld %6.2f%%\n", info.counts, info.missed,
	       ((info.counts - info.missed) * 1.0 / info.counts) * 100);

	bpf_map_delete_elem(fd, &zero);
	return;
}

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct icstat_bpf *obj;
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
		goto cleanup;
	}

	obj = icstat_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		err = 1;
		goto cleanup;
	}

	err = icstat_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object");
		goto cleanup;
	}

	err = icstat_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF program");
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing icache lookups... Hit Ctrl-C to end.\n");
	if (env.timestamp)
		printf("%8s ", "TIME");
	printf("%10s %10s %7s\n", "REFS", "MISSES", "HIT");

	while (!exiting) {
		sleep(env.interval);
		print_map(obj);
	}

cleanup:
	cleanup_core_btf(&open_opts);
	icstat_bpf__destroy(obj);

	return err != 0;
}
