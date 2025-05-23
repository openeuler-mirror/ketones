// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "wakeuptime.h"
#include "wakeuptime.skel.h"
#include "trace_helpers.h"

struct env {
	pid_t pid;
	bool user_threads_only;
	bool verbose;
	bool folded;
	int stack_storage_size;
	int perf_max_stack_depth;
	__u64 min_block_time;
	__u64 max_block_time;
	int duration;
} env = {
	.verbose = false,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.min_block_time = 1,
	.max_block_time = -1,
	.duration = 99999999,
};

const char *argp_program_version = "wakeuptime 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize sleep to wakeup time by waker kernel stack.\n"
"\n"
"USAGE: wakeuptime [-h] [-p PID | -u] [-v] [-f] [-m MIN-BLOCK-TIME] "
"[-M MAX-BLOCK-TIME] ]--perf-max-stack-depth] [--stack-storage-size] [duration]\n"
"EXAMPLES:\n"
"       wakeuptime              # trace blocked time with waker stacks\n"
"       wakeuptime 5            # trace for 5 seconds only\n"
"       wakeuptime -f 5         # 5 seconds, and output in folded format\n"
"       wakeuptime -u           # don't include kernel threads (user only)\n"
"       wakeuptime -p 185       # trace for PID 185 only\n";

#define OPT_PERF_MAX_STACK_DEPTH	1	/* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2	/* --stack-storage-size */

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only", 0 },
	{ "verbose", 'v', NULL, 0, "Show raw address", 0 },
	{ "folded", 'f', NULL, 0, "output folded format", 0 },
	{ "user-threads-only", 'u', NULL, 0, "User threads only (no kernel threads)", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH, "PERF_MAX_STACK_DEPTH",
		0, "The limit for both kernel and user stack traces (default 127)", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK_STORAGE_SIZE",
		0, "The number of unique stack traces that can be stored and displayed (default 1024)", 0 },
	{ "min-block-time", 'm', "MIN-BLOCK-TIME", 0,
		"The amount of time in microseconds over which we store traces (default 1)", 0 },
	{ "max-block-time", 'M', "MAX-BLOCK-TIME", 0,
		"The amount of time in microseconds under which we store traces (default U64_MAX)", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
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
	case 'f':
		env.folded = true;
		break;
	case 'u':
		env.user_threads_only = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno) {
			warning("Invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno) {
			warning("Invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		errno = 0;
		env.min_block_time = strtol(arg, NULL, 10);
		if (errno) {
			warning("Invalid min block time (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'M':
		errno = 0;
		env.max_block_time = strtol(arg, NULL, 10);
		if (errno) {
			warning("Invalid max block time (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.duration = strtol(arg, NULL, 10);
			if (errno || env.duration <= 0) {
				warning("Invalid duration (in s)\n");
				argp_usage(state);
			}
		} else {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
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
{}

static void print_map(struct ksyms *ksyms, struct wakeuptime_bpf *bpf_obj)
{
	struct key_t lookup_key = {}, next_key;
	unsigned long *ip;
	int counts_fd, stack_traces_fd;
	__u64 val;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		warning("Failed to alloc ip\n");
		return;
	}

	counts_fd = bpf_map__fd(bpf_obj->maps.counts);
	stack_traces_fd = bpf_map__fd(bpf_obj->maps.stackmap);

	while (!bpf_map_get_next_key(counts_fd, &lookup_key, &next_key)) {
		int err = bpf_map_lookup_elem(counts_fd, &next_key, &val);

		if (err < 0) {
			warning("Failed to lookup info: %d\n", err);
			free(ip);
			return;
		}

		if (!env.folded)
			printf("\n    %-16s %s\n", "target:", next_key.target);
		else
			printf("%s;", next_key.target);

		lookup_key = next_key;

		err = bpf_map_lookup_elem(stack_traces_fd, &next_key.wake_stack_id, ip);
		if (err < 0)
			folded_printf(env.folded, "[Missed Kernel Stack]");

		for (int i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			const struct ksym *ksym = ksyms__map_addr(ksyms, ip[i]);

			if (!env.folded) {
				if (ksym)
					printf("    %-16lx %s+0x%lx\n", ip[i], ksym->name, ip[i] - ksym->addr);
				else
					printf("    %-16lx Unknown\n", ip[i]);

			} else {
				printf("%s;", ksym ? ksym->name : "Unknown");
			}
		}

		/* To convert val in microseconds */
		val /= 1000;

		if (!env.folded) {
			printf("    %-16s %s\n", "waker:", next_key.waker);
			printf("        %lld\n", val);
		} else {
			printf("%s", next_key.waker);
			printf(" %lld\n", val);
		}
	}

	if (!env.folded)
		printf("Detaching...\n");

	free(ip);
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	DEFINE_SKEL_OBJECT(bpf_obj);
	struct ksyms *ksyms = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	if (env.min_block_time >= env.max_block_time) {
		warning("min_block_time should be smaller than max_block_time\n");
		return 1;
	}

	if (env.user_threads_only && env.pid > 0)
		warning("use either -u or -p");

	libbpf_set_print(libbpf_print_fn);

	bpf_obj = SKEL_OPEN();
	if (!bpf_obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	if (probe_tp_btf("sched_switch")) {
		bpf_program__set_autoload(bpf_obj->progs.sched_switch_raw, false);
		bpf_program__set_autoload(bpf_obj->progs.sched_wakeup_raw, false);
	} else {
		bpf_program__set_autoload(bpf_obj->progs.sched_switch_btf, false);
		bpf_program__set_autoload(bpf_obj->progs.sched_wakeup_btf, false);
	}

	bpf_obj->rodata->target_pid = env.pid;
	bpf_obj->rodata->min_block_ns = env.min_block_time;
	bpf_obj->rodata->max_block_ns = env.max_block_time;
	bpf_obj->rodata->user_threads_only = env.user_threads_only;

	bpf_map__set_value_size(bpf_obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(bpf_obj->maps.stackmap, env.stack_storage_size);

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("Failed to load kallsyms\n");
		goto cleanup;
	}

	err = SKEL_LOAD(bpf_obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = SKEL_ATTACH(bpf_obj);
	if (err) {
		warning("Failed to attach BPF programs\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Cann't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (!env.folded) {
		printf("Tracing blocked time (us) by kernel stack");
		if (env.duration < 99999999)
			printf(" for %d secs\n", env.duration);
		else
			printf("... Hit Ctrl-C to end.\n");
	}
	sleep(env.duration);
	print_map(ksyms, bpf_obj);

cleanup:
	SKEL_DESTROY(bpf_obj);
	ksyms__free(ksyms);

	return err != 0;
}
