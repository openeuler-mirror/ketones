// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "hardirqs.h"
#include "hardirqs.skel.h"
#include "trace_helpers.h"

struct env {
	bool count;
	bool distributed;
	bool nanoseconds;
	time_t interval;
	int times;
	bool timestamp;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "hardirqs 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize hard irq event time as histograms.\n"
"\n"
"USAGE: hardirqs [--help] [-T] [-N] [-d] [interval] [count] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    hardirqs            # sum hard irq event time\n"
"    hardirqs -d         # show hard irq event time as histograms\n"
"    hardirqs 1 10       # print 1 second summaries, 10 times\n"
"    hardirqs -c CG      # Trace process under cgroupsPath CG\n"
"    hardirqs -NT 1      # 1s summaries, nanoseconds, and timestamps\n";

static const struct argp_option opts[] = {
	{ "count", 'C', NULL, 0, "Show event counts instead of timing" },
	{ "distributed", 'd', NULL, 0, "Show distributions as histograms" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "nanoseconds", 'N', NULL, 0, "Output in nanoseconds" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		env.distributed = true;
		break;
	case 'C':
		env.count = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'N':
		env.nanoseconds = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				warning("Invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 0);
			if (errno) {
				warning("Invalid times\n");
				argp_usage(state);
			}
		} else {
			warning("Unrecongnized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int print_map(struct bpf_map *map)
{
	irq_key_t lookup_key = {}, next_key;
	info_t info;
	int fd, err;
	const char *units = env.nanoseconds ? "nsecs" : "usecs";

	if (env.count)
		printf("%-26s %11s\n", "HARDIRQ", "TOTAL_count");
	else if (!env.distributed)
		printf("%-26s %6s%5s\n", "HARDIRQ", "TOTAL_", units);

	fd = bpf_map__fd(map);
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &info);
		if (err < 0) {
			warning("failed to lookup infos: %d\n", err);
			return -1;
		}
		if (!env.distributed) {
			printf("%-26s %11llu\n", next_key.name, info.count);
		} else {
			printf("hardirq = %s\n", next_key.name);
			print_log2_hist(info.slots, MAX_SLOTS, units);
		}
		lookup_key = next_key;
	}

	memset(&lookup_key, 0, sizeof(lookup_key));

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			warning("failed to cleanup infos: %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct hardirqs_bpf *bpf_obj;
	char ts[32];
	int err;
	int idx, memcg_map_fd;
	int memcg_fd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	if (env.count && env.distributed) {
		warning("count, distributed cann't be used together.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	bpf_obj = hardirqs_bpf__open();
	if (!bpf_obj) {
		warning("failed to open BPF object\n");
		return 1;
	}

	if (probe_tp_btf("irq_handler_entry")) {
		bpf_program__set_autoload(bpf_obj->progs.irq_handler_entry_raw, false);
		bpf_program__set_autoload(bpf_obj->progs.irq_handler_exit_raw, false);
		if (env.count)
			bpf_program__set_autoload(bpf_obj->progs.irq_handler_exit_btf, false);
	} else {
		bpf_program__set_autoload(bpf_obj->progs.irq_handler_entry_btf, false);
		bpf_program__set_autoload(bpf_obj->progs.irq_handler_exit_btf, false);
		if (env.count)
			bpf_program__set_autoload(bpf_obj->progs.irq_handler_exit_raw, false);
	}

	/* initialize global data (filtering options) */
	bpf_obj->rodata->filter_memcg = env.cg;
	bpf_obj->rodata->do_count = env.count;

	if (!env.count) {
		bpf_obj->rodata->target_dist = env.distributed;
		bpf_obj->rodata->target_ns = env.nanoseconds;
	}

	err = hardirqs_bpf__load(bpf_obj);
	if (err) {
		warning("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* update cgroup path fd to map */
	if (env.cg) {
		idx = 0;
		memcg_map_fd = bpf_map__fd(bpf_obj->maps.cgroup_map);
		memcg_fd = open(env.cgroupspath, O_RDONLY);
		if (memcg_fd < 0) {
			warning("Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(memcg_map_fd, &idx, &memcg_fd, BPF_ANY)) {
			warning("Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	err = hardirqs_bpf__attach(bpf_obj);
	if (err) {
		warning("Failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	if (env.count)
		printf("Tracing hard irq events... Hit Ctrl-C to end.\n");
	else
		printf("Tracing hard irq event time... Hit Ctrl-C to end.\n");

	/* Main loop */
	for (;;) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s\n", ts);
		}

		err = print_map(bpf_obj->maps.infos);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	hardirqs_bpf__destroy(bpf_obj);
	if (memcg_fd > 0)
		close(memcg_fd);

	return err != 0;
}
