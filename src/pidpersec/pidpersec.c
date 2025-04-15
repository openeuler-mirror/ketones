// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "pidpersec.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;
static bool verbose = false;

const char *argp_program_version = "pidpersec 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Count new procesess (via fork)\n"
"\n"
"USAGE:      pidpersec [-v]\n"
"\n"
"Examples:\n"
"    pidpersec              # Count new process every seconds\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
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
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
	struct pidpersec_bpf *obj;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = pidpersec_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	if (probe_tp_btf("sched_process_fork"))
		bpf_program__set_autoload(obj->progs.sched_process_fork_raw, false);
	else
		bpf_program__set_autoload(obj->progs.sched_process_fork, false);

	err = pidpersec_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		goto cleanup;
	}

	if (!obj->bss) {
		warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		err = 1;
		goto cleanup;
	}

	err = pidpersec_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF object\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing... Ctrl-C to end.\n");

	while (!exiting) {
		sleep(1);

		__u64 counts = __atomic_exchange_n(&obj->bss->counts, 0, __ATOMIC_RELAXED);
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%s: PIDs/sec: %llu\n", ts, counts);
	}

cleanup:
	pidpersec_bpf__destroy(obj);

	return err != 0;
}
