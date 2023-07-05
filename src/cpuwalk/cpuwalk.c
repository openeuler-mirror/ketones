// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "cpuwalk.h"
#include "cpuwalk.skel.h"
#include "trace_helpers.h"
#include "btf_helpers.h"
#include <sys/syscall.h>
#include <linux/perf_event.h>

static volatile sig_atomic_t exiting;

static bool verbose = false;
static int frequency = 99;

const char *argp_program_version = "cpuwalk 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Sample which CPUs are executing processes\n"
"\n"
"USAGE: cpuwalk [-v] [-f FREQUENCY]\n"
"\n"
"Example:\n"
"    cpuwalk               # sampling cpu\n"
"    cpuwalk -f 199        # sampling at 199HZ\n";

static const struct argp_option opts[] = {
	{ "frequency", 'f', "FREQUENCY", 0, "Sample with a certain frequency" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
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
	case 'f':
		frequency = argp_parse_long(key, arg, state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(struct bpf_program *prog,
				      struct bpf_link *links[])
{
	for (int i = 0; i < nr_cpus; i++) {
		struct perf_event_attr attr = {
			.type = PERF_TYPE_SOFTWARE,
			.freq = 1,
			.sample_freq = frequency,
			.config = PERF_COUNT_SW_CPU_CLOCK,
		};

		int fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;

			warning("Failed to init perf sampling: %s\n", strerror(errno));
			return -1;
		}

		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			warning("Failed to attach perf event on CPU #%d!\n", i);
			close(fd);
			return -1;
		}
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

static struct hist zero;

static void print_hist(struct cpuwalk_bpf__bss *bss)
{
	struct hist hist = bss->hist;

	printf("\n");

	bss->hist = zero;
	print_linear_hist(hist.slots, MAX_CPU_NR, 0, 1, "cpuwalk");
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_link *links[MAX_CPU_NR] = {};
	struct cpuwalk_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		warning("Failed to get # of possible cpus: '%s'!\n",
			strerror(-nr_cpus));
		return 1;
	}

	if (nr_cpus > MAX_CPU_NR) {
		warning("The number of cpu cores is too big, pleace increase "
			"MAX_CPU_NR's value and recompile\n");
		return 1;
	}

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return 1;
	}

	obj = cpuwalk_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF objects\n");
		return 1;
	}

	err = cpuwalk_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF objects\n");
		goto cleanup;
	}

	if (!obj->bss) {
		warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = open_and_attach_perf_event(obj->progs.do_sample, links);
	if (err)
		goto cleanup;

	printf("Sampling CPU at %dhz... Hit Ctrl-C to end.\n", frequency);

	signal(SIGINT, sig_handler);

	sleep(-1);
	print_hist(obj->bss);

cleanup:
	for (int i = 0; i < nr_cpus; i++)
		bpf_link__destroy(links[i]);

	cpuwalk_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
