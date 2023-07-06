// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Based on funcslower.py - Copyright 2017, Sasha Goldshtein

#include "commons.h"
#include "funcslower.h"
#include "funcslower.skel.h"
#include "compat.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"
#include <sys/param.h>

#define MAX_FUNCTIONS	10

static volatile sig_atomic_t exiting = 0;
static struct ksyms *ksyms;
static struct syms_cache *syms_cache;

static struct env {
	bool need_grab_args;
	bool need_kernel_stack;
	bool need_user_stack;
	bool pid;
	__u64 duration_ns;
	bool ms;
	bool timestamp;
	bool time;
	bool verbose;
	int arguments;
	const char *functions[MAX_FUNCTIONS];
	int perf_max_stack_depth;
	int stack_storage_size;
} env = {
	.duration_ns = 1000000,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
};

const char *argp_progarm_version = "funcslower 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"funcslower  Trace slow kernel or user function calls.\n"
"\n"
"USAGE: funcslower [-h] [-p PID] [-m MIN_MS] [-u MIN_US] [-a ARGUMENTS]\n"
"                  [-T] [-t] [-v] function [function ...]\n"
"\n"
"Example:\n"
"  ./funcslower vfs_write        # trace vfs_write calls slower than 1ms\n"
"  ./funcslower -m 10 vfs_write  # same, but slower than 10ms\n"
"  ./funcslower -u 10 c:open     # trace open calls slower than 10us\n"
"  ./funcslower -p 135 c:open    # trace pid 135 only\n"
"  ./funcslower c:malloc c:free  # trace both malloc and free slower than 1ms\n"
"  ./funcslower -a 2 c:open      # show first two arguments to open\n"
"  ./funcslower -UK -m 10 c:open # Show user and kernel stack frame of open calls slower than 10ms\n";

#define OPT_PERF_MAX_STACK_DEPTH	1	/* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2	/* --stack-storage-size */

const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "pid", 'p', "PID", 0, "trace this PID only" },
	{ "min-ms", 'm', "MIN-MS", 0, "minimum duration to trace (ms)" },
	{ "min-us", 'u', "MIN-US", 0, "minimum duration to trace (us)" },
	{ "arguments", 'a', "ARGUMENTS", 0, "print this many entry arguments, as hex" },
	{ "time", 'T', NULL, 0, "show HH:MM:SS timestamp" },
	{ "timestamp", 't', NULL, 0, "show timestamp in seconds at us resolution" },
	{ "user-stack", 'U', NULL, 0, "output user stack trace" },
	{ "kernel-stack", 'K', NULL, 0, "output kernel stack trace" },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH, "PERF_MAX_STACK_DEPTH",
	   0, "The limit for both kernel and user stack traces (default 127)" },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK_STORAGE_SIZE",
	   0, "The number of unique stack traces that can be stored and displayed (default 1024)" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case OPT_PERF_MAX_STACK_DEPTH:
		env.perf_max_stack_depth = argp_parse_long(key, arg, state);
		break;
	case OPT_STACK_STORAGE_SIZE:
		env.stack_storage_size = argp_parse_long(key, arg, state);
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'm':
		env.duration_ns = argp_parse_long(key, arg, state) * 1000000;
		break;
	case 'u':
		env.duration_ns = argp_parse_long(key, arg, state) * 1000;
		break;
	case 'U':
		env.need_user_stack = true;
		break;
	case 'K':
		env.need_kernel_stack = true;
		break;
	case 'a':
		env.need_grab_args = true;
		env.arguments = argp_parse_long(key, arg, state);
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'T':
		env.time = true;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num >= MAX_FUNCTIONS) {
			warning("Too many function, limit to %d\n", MAX_FUNCTIONS);
			argp_usage(state);
		}
		env.functions[state->arg_num] = arg;
		break;
	case ARGP_KEY_END:
		if (env.duration_ns >= 1000000)
			env.ms = true;
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

static void autoload_programs(struct funcslower_bpf *obj)
{
	char buf[128] = {};

	for (int i = 0; i < ARRAY_SIZE(env.functions) && env.functions[i]; i++) {
		bool is_kernel_func = !strchr(env.functions[i], ':');

		if (is_kernel_func)
			sprintf(buf, "trace_k%d", i);
		else
			sprintf(buf, "trace_u%d", i);

		for (int j = 0; j < obj->skeleton->prog_cnt; j++) {
			if (strcmp(buf, obj->skeleton->progs[j].name) == 0) {
				bpf_program__set_autoload(*obj->skeleton->progs[j].prog, true);
				break;
			}
		}
	}
}

static void attach_programs(struct funcslower_bpf *obj)
{
	char buf[128] = {};

	for (int i = 0; i < ARRAY_SIZE(env.functions) && env.functions[i]; i++) {
		bool is_kernel_func = !strchr(env.functions[i], ':');

		if (is_kernel_func) {
			sprintf(buf, "trace_k%d", i);
			for (int j = 0; j < obj->skeleton->prog_cnt; j++) {
				if (strcmp(buf, obj->skeleton->progs[j].name) == 0) {
					bpf_program__attach_kprobe(*obj->skeleton->progs[j].prog,
								   false,
								   env.functions[i]);
					break;
				}
			}
			bpf_program__attach_kprobe(obj->progs.trace_return_k, true,
						   env.functions[i]);
		} else {
			const char *binary;
			char *function;
			char bin_path[PATH_MAX];
			off_t func_off;

			binary = strdup(env.functions[i]);

			function = strchr(binary, ':');
			if (!function) {
				warning("Binary should have contained ':' (internal bug!)\n");
				goto free_binary;
			}

			*function = '\0';
			function++;

			if (resolve_binary_path(binary, getpid(), bin_path, sizeof(bin_path)))
				goto free_binary;

			func_off = get_elf_func_offset(bin_path, function);
			if (func_off < 0) {
				warning("Could not find %s in %s\n", function, bin_path);
				goto free_binary;
			}

			sprintf(buf, "trace_u%d", i);
			for (int j = 0; j < obj->skeleton->prog_cnt; j++) {
				if (strcmp(buf, obj->skeleton->progs[j].name) == 0) {
					bpf_program__attach_uprobe(*obj->skeleton->progs[j].prog,
								   false,
								   env.pid ? env.pid : -1, bin_path, func_off);
					break;
				}
			}

			bpf_program__attach_uprobe(obj->progs.trace_return_u, true,
						   env.pid ? env.pid : -1, bin_path, func_off);

free_binary:
			free((void *)binary);
		}
	}
}

static int print_stack(struct funcslower_bpf *obj, struct event *e)
{
	unsigned long *ip;
	const struct syms *syms;
	int idx = 0;

	if (!env.need_user_stack && !env.need_kernel_stack)
		return 0;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		warning("Failed to alloc ip\n");
		return 0;
	}

	if (!env.need_kernel_stack || e->kernel_stack_id == -1)
		goto print_ustack;

	if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.stack_trace),
				&e->kernel_stack_id, ip)) {
		warning("    [Missed Kernel Stack]\n");
		goto print_ustack;
	}

	for (int i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
		const struct ksym *ksym = ksyms__map_addr(ksyms, ip[i]);

		if (ksym)
			printf("    #%-2d 0x%lx %s+0x%lx\n", idx++, ip[i], ksym->name, ip[i] - ksym->addr);
		else
			printf("    #%-2d 0x%lx [unknown]\n", idx++, ip[i]);
	}

print_ustack:
	if (!env.need_user_stack || e->user_stack_id == -1)
		goto out;

	if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.stack_trace),
				&e->user_stack_id, ip)) {
		warning("    [Missed User Stack]\n");
		goto out;
	}

	syms = syms_cache__get_syms(syms_cache, e->pid_tgid >> 32);
	for (int i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
		if (!syms)
			printf("    #%-2d 0x%016lx [unknown]\n", idx++, ip[i]);
		else {
			const struct sym *sym;
			char *dso_name;
			unsigned long dso_offset;

			sym = syms__map_addr_dso(syms, ip[i], &dso_name, &dso_offset);
			printf("    #%-2d 0x%016lx", idx++, ip[i]);
			if (sym) {
				printf(" %s+0x%lx", sym->name, sym->offset);
				if (dso_name)
					printf(" (%s+0x%lx)", dso_name, dso_offset);
			} else {
				printf(" [unknown]");
			}
			printf("\n");
		}
	}

out:
	free(ip);
	return 0;
}

static void print_args(__u64 args[])
{
	for (int i = 0; i < MIN(MAX_ARGS, env.arguments); i++)
		printf(" 0x%llx", args[i]);
	printf("\n");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	struct funcslower_bpf *obj = ctx;

	if (env.time) {
		char ts[16];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%-10s ", ts);
	} else if (env.timestamp) {
		printf("%-10.6f ", time_since_start());
	}

	char retval[20];
	sprintf(retval, "0x%llx", e->retval);

	printf("%-16s %-10lld %10.2f %16s %s", e->comm, e->pid_tgid >> 32,
	       e->duration_ns / (env.ms ? 1e6 : 1e3), retval,
	       env.functions[e->id]);

	print_args(e->args);
	print_stack(obj, e);
	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %lld events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct funcslower_bpf *obj;
	struct bpf_buffer *buf;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = funcslower_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->need_grab_args = env.need_grab_args;
	obj->rodata->need_kernel_stack = env.need_kernel_stack;
	obj->rodata->need_user_stack = env.need_user_stack;
	obj->rodata->target_pid = env.pid;
	obj->rodata->duration_ns = env.duration_ns;
	bpf_map__set_value_size(obj->maps.stack_trace, env.perf_max_stack_depth * sizeof(__u64));
	bpf_map__set_max_entries(obj->maps.stack_trace, env.stack_storage_size);

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = 1;
		warning("Failed to create ring/perf buffer\n");
		goto cleanup;
	}

	autoload_programs(obj);
	err = funcslower_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF objects: %d\n", err);
		goto cleanup;
	}

	attach_programs(obj);
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		err = 1;
		warning("Failed seting signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("Failed to load kallsyms\n");
		err = 1;
		goto cleanup;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		warning("Failed to create syms_cache\n");
		err = 1;
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, obj);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	printf("Tracing function calls slower than %g %s... Ctrl+C to quit.\n",
	       env.duration_ns / (env.ms ? 1e6 : 1e3), env.ms ? "ms" : "us");
	printf("%-10s %-16s %-10s %10s %16s %s", "TIME", "COMM", "PID",
	       env.ms ? "LAT(ms)" : "LAT(us)", "RETVAL", "FUNC");
	if (env.need_grab_args)
		printf(" ARGS");
	printf("\n");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Failed to polling ring/perf buffer: %d\n", err);
			goto cleanup;
		}

		/* reset err to 0 when exiting */
		err = 0;
	}

cleanup:
	funcslower_bpf__destroy(obj);
	bpf_buffer__free(buf);
	ksyms__free(ksyms);
	syms_cache__free(syms_cache);

	return err != 0;
}
