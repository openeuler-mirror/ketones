// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Base on stacksnoop.py - Brendan Gregg

#include "commons.h"
#include "stacksnoop.h"
#include "stacksnoop.skel.h"
#include "compat.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;

static struct env {
	bool print_offset;
	bool verbose;
	pid_t pid;
	const char *function;
	int perf_max_stack_depth;
	int stack_map_max_entries;
} env = {
	.perf_max_stack_depth = 127,
	.stack_map_max_entries = 1024,
};

struct ksyms *ksyms;
static __u64 *stacks;

const char *argp_program_version = "stacksnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace a kernel function and print all kernel stack traces.\n"
"\n"
"USAGE: stacksnoop [-h] [-v] [-s] [-p PID] function\n";

#define OPT_PERF_MAX_STACK_DEPTH	1	/* --perf-max-stack-depth */
#define OPT_STACK_MAP_MAX_ENTRIES	2	/* --stack-map-max-entries */

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "show extra columns", 0 },
	{ "pid", 'p', "PID", 0, "Trace PID only", 0 },
	{ "offset", 's', NULL, 0, "Also show symbol offsets", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH, "PERF_MAX_STACK_DEPTH",
	  0, "The limit for both kernel and user stack traces (default 127)", 0 },
	{ "stack-map-max-entries", OPT_STACK_MAP_MAX_ENTRIES, "STACK_MAP_MAX_ENTRIES",
	  0, "The number of unique stack traces that can be stored and displayed (default 1024)", 0 },
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
	case 's':
		env.print_offset = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		env.perf_max_stack_depth = argp_parse_long(key, arg, state);
		break;
	case OPT_STACK_MAP_MAX_ENTRIES:
		env.stack_map_max_entries = argp_parse_long(key, arg, state);
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num != 0) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}

		env.function = strdup(arg);
		break;
	case ARGP_KEY_END:
		if (!env.function)
			argp_usage(state);
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
	int fd = *(int *)ctx;

	if (env.verbose)
		printf("%-18s %-12s %-7s %-3s %s\n", "TIME(s)", "COMM", "PID",
		       "CPU", "FUNCTION");
	else
		printf("%-18s %s\n", "TIME(s)", "FUNCTION");

	printf("%-18.9f ", time_since_start());
	if (env.verbose)
		printf("%-12.12s %-7d %-3d %s\n",
		       e->comm, e->pid, e->cpu, env.function);
	else
		printf("%s\n", env.function);

	bpf_map_lookup_elem(fd, &e->stack_id, stacks);
	for (size_t i = 0; i < env.perf_max_stack_depth; i++) {
		if (!stacks[i])
			break;

		const struct ksym *ksym = ksyms__map_addr(ksyms, stacks[i]);
		if (ksym) {
			printf("\t%zu [<%016llx>] %s", i, stacks[i], ksym->name);
			if (env.print_offset) {
				printf("+0x%llx", stacks[i] - ksym->addr);
				if (ksym->module)
					printf(" [%s]", ksym->module);
			}

			printf("\n");
		} else {
			printf("\t%zu [<%016llx>] <%s>\n", i, stacks[i], "null sym");
		}
	}

	printf("\n");

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static bool check_fentry()
{
	if (fentry_can_attach(env.function, NULL))
		return true;
	return false;
}

static int fentry_set_attach_target(struct stacksnoop_bpf *obj)
{
	return bpf_program__set_attach_target(obj->progs.fentry_function, 0, env.function);
}

static int attach_kprobes(struct stacksnoop_bpf *obj)
{
	if (kprobe_exists(env.function)) {
		obj->links.kprobe_function = bpf_program__attach_kprobe(obj->progs.kprobe_function,
									0,
									env.function);
		if (!obj->links.kprobe_function)
			return 1;
	} else {
		return 1;
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
	struct bpf_buffer *buf = NULL;
	struct stacksnoop_bpf *obj;
	int err;
	bool support_fentry;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = stacksnoop_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	/* alloc space for storing a stack trace */
	stacks = calloc(env.perf_max_stack_depth, sizeof(*stacks));
	if (!stacks) {
		warning("Failed to allocate stack array\n");
		err = -ENOMEM;
		goto cleanup;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer\n");
		err = 1;
		goto cleanup;
	}

	bpf_map__set_value_size(obj->maps.stack_traces,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stack_traces, env.stack_map_max_entries);

	support_fentry = check_fentry();
	if (support_fentry) {
		err = fentry_set_attach_target(obj);
		if (err) {
			warning("Failed to set fentry attach: %d\n", err);
			goto cleanup;
		}
		bpf_program__set_autoload(obj->progs.kprobe_function, false);
	} else {
		bpf_program__set_autoload(obj->progs.fentry_function, false);
	}

	err = stacksnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = support_fentry ? stacksnoop_bpf__attach(obj) : attach_kprobes(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("Failed to load ksyms\n");
		err = -ENOMEM;
		goto cleanup;
	}

	int fd = bpf_map__fd(obj->maps.stack_traces);
	err = bpf_buffer__open(buf, handle_event, handle_lost_events, &fd);

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
	bpf_buffer__free(buf);
	stacksnoop_bpf__destroy(obj);
	ksyms__free(ksyms);
	free(stacks);

	return err != 0;
}
