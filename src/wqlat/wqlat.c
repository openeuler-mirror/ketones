// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2024 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>

#include "commons.h"
#include "wqlat.skel.h"
#include "wqlat.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;

static struct {
	bool verbose;
	bool timestamp;
	bool nanoseconds;
	int interval;
	int count;
	const char *wq_name;
	bool show_per_workqueue;
	bool target_workqueue;
} env = {
	.interval = 99999999,
	.count = 99999999,
};

const char *argp_program_version = "wqlat 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"wqlat Summarize kernel workqueue latency as a histogram.\n"
"\n"
"USAGE: wqlat [-h] [-T] [-N] [-W] [-w WQNAME] [interval] [count]\n"
"\n"
"Examples:\n"
"    ./wqlat                   # summarize workqueue latency as a histogram\n"
"    ./wqlat 1 10              # print 1 second summaries, 10 times\n"
"    ./wqlat -W 1 10           # print 1 second, 10 times per workqueue\n"
"    ./wqlat -NT 1             # 1s summaries, nanoseconds, and timestamps\n"
"    ./wqlat -w nvmet_tcp_wq 1 # 1s summaries for workqueue nvmet_tcp_wq\n";

static struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "nanoseconds", 'N', NULL, 0, "Output in nanoseconds", 0 },
	{ NULL, 'w', "WQNAME", 0, "Trace WQNAME only", 0 },
	{ NULL, 'W', NULL, 0, "Output for per workqueue", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help", 0 },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'N':
		env.nanoseconds = true;
		break;
	case 'W':
		env.show_per_workqueue = true;
		break;
	case 'w':
		env.wq_name = arg;
		env.target_workqueue = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0) {
			env.interval = argp_parse_long(key, arg, state);
			break;
		} else if (state->arg_num == 1) {
			env.count = argp_parse_long(key, arg, state);
			break;
		} else {
			warning("Unrecongnized positional argument: %s\n", arg);
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
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int print_dists(struct wqlat_bpf *obj)
{
	int fd = bpf_map__fd(obj->maps.dists);
	struct wq_key key = {}, next_key;
	struct wq_info value;
	int err = 0;
	const char *units = env.nanoseconds ? "nsecs" : "usecs";
	int count = 0;

	while (!bpf_map_get_next_key(fd, &key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &value);
		if (err) {
			warning("Error looking up map element\n");
			goto cleanup;
		}

		if (env.show_per_workqueue)
			printf("wqname = %s\n", next_key.wq_name);
		print_log2_hist(value.slots, MAX_SLOTS, units);
		printf("\n");
		key = next_key;
		count++;
	}

cleanup:
	memset(&key, 0, sizeof(key));
	while (!bpf_map_get_next_key(fd, &key, &next_key)) {
		bpf_map_delete_elem(fd, &next_key);
		key = next_key;
	}

	return count;
}

static int print_maps(struct wqlat_bpf *obj)
{
	printf("Tracing work queue request latency time... Hit Ctrl-C to end.\n");

	while (!exiting) {
		sleep(env.interval);

		if (env.timestamp) {
			char ts[16];

			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s\n", ts);
		}

		int count = print_dists(obj);
		if (!count)
			continue;

		if (!--env.count)
			break;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	const struct argp argp = {
		.parser = parse_arg,
		.options = opts,
		.doc = argp_program_doc,
	};
	struct wqlat_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return err;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = wqlat_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	if (!obj->bss) {
		warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		err = 1;
		goto cleanup;
	}

	obj->rodata->target_ns = env.nanoseconds;
	obj->rodata->show_per_workqueue = env.show_per_workqueue;
	if (env.target_workqueue) {
		obj->rodata->target_workqueue = env.target_workqueue;
		memcpy(obj->bss->workqueue_name, env.wq_name, WQ_NAME_LEN);
	}

	err = wqlat_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = wqlat_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		err = 1;
		warning("Failed to set signal handler\n");
		goto cleanup;
	}

	err = print_maps(obj);

cleanup:
	wqlat_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
