// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "offcputime.h"
#include "offcputime.skel.h"
#include "trace_helpers.h"

static struct env {
	pid_t pid;
	pid_t tid;
	bool user_threads_only;
	bool user_stacks_only;
	bool kernel_threads_only;
	bool kernel_stacks_only;
	int stack_storage_size;
	int perf_max_stack_depth;
	__u64 min_block_time;
	__u64 max_block_time;
	long state;
	int duration;
	bool verbose;
	bool folded;
} env = {
	.pid = -1,
	.tid = -1,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.min_block_time = 1,
	.max_block_time = -1,
	.state = -1,
	.duration = 99999999,
};

const char *argp_program_version = "offcputime 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize off-CPU time by stack trace.\n"
"\n"
"USAGE: offcputime [--help] [-p PID | -u | -k] [-m MIN-BLOCK-TIME] [-f] "
"[-M MAX-BLOCK-TIME] [--state] [--perf-max-stack-depth] [--stack-storage-size] "
"[duration]\n\n"
"EXAMPLES:\n"
"    offcputime             # trace off-CPU stack time until Ctrl-C\n"
"    offcputime 5           # trace for 5 seconds only\n"
"    offcputime -f 5        # 5 seconds, and output in folded format\n"
"    offcputime -m 1000     # trace only events that last more than 1000 usec\n"
"    offcputime -M 10000    # trace only events that last less than 10000 usec\n"
"    offcputime -p 185      # only trace threads for PID 185\n"
"    offcputime -t 188      # only trace thread 188\n"
"    offcputime -u          # only trace user threads (no kernel)\n"
"    offcputime -k          # only trace kernel threads (no user)\n"
"    offcputime -U          # only show user space stacks (no kernel)\n"
"    offcputime -K          # only show kernel space stacks (no user)\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */
#define OPT_STATE			3 /* --state */

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "tid", 't', "TID", 0, "Trace this TID only" },
	{ "user-threads-only", 'u', NULL, 0,
	  "User threads only (no kernel threads)" },
	{ "user-stacks-only", 'U', NULL, 0,
	  "show stacks from user space only (no kernel space stacks)" },
	{ "kernel-threads-only", 'k', NULL, 0,
	  "Kernel threads only (no user threads)" },
	{ "kernel-stacks-only", 'K', NULL, 0,
	  "show stacks from kernel space only (no user space stacks)" },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)" },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)" },
	{ "min-block-time", 'm', "MIN-BLOCK-TIME", 0,
	  "the amount of time in microseconds over which we store traces (default 1)" },
	{ "max-block-time", 'M', "MAX-BLOCK-TIME", 0,
	  "the amount of time in microseconds under which we store traces (default U64_MAX)" },
	{ "state", OPT_STATE, "STATE", 0,
	  "filter on this thread state bitmask (eg, 2 == TASK_UNINTERRUPTIBLE) see include/linux/sched.h" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "folded", 'f', NULL, 0, "output folded format" },
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
	case 'f':
		env.folded = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		errno = 0;
		env.tid = strtol(arg, NULL, 10);
		if (errno || env.tid <= 0) {
			warning("Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'u':
		env.user_threads_only = true;
		break;
	case 'U':
		env.user_stacks_only = true;
		break;
	case 'k':
		env.kernel_threads_only = true;
		break;
	case 'K':
		env.kernel_stacks_only = true;
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
		env.min_block_time = strtoll(arg, NULL, 10);
		if (errno) {
			warning("Invalid min block time (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'M':
		errno = 0;
		env.max_block_time = strtoll(arg, NULL, 10);
		if (errno) {
			warning("Invalid max block time (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STATE:
		errno = 0;
		env.state = strtol(arg, NULL, 10);
		if (errno || env.state < 0 || env.state > 2) {
			warning("Invalid task state: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			warning("Invalid duration (in s): %s\n", arg);
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

static void print_map(struct ksyms *ksyms, struct syms_cache *syms_cache,
		      struct offcputime_bpf *bpf_obj)
{
	offcpu_key_t lookup_key = {}, next_key;
	int err, ifd, sfd;
	unsigned long *ip;
	offcpu_val_t val;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		warning("Failed to alloc ip\n");
		return;
	}

	if (env.folded)
		env.verbose = false;

	ifd = bpf_map__fd(bpf_obj->maps.info);
	sfd = bpf_map__fd(bpf_obj->maps.stackmap);

	while (!bpf_map_get_next_key(ifd, &lookup_key, &next_key)) {
		int idx = 0, i;
		const struct syms *syms;

		lookup_key = next_key;

		err = bpf_map_lookup_elem(ifd, &next_key, &val);
		if (err < 0) {
			warning("Failed to lookup info: %d\n", err);
			goto cleanup;
		}

		if (val.delta == 0)
			continue;

		if (env.folded)
			printf("%s;", val.comm);

		if (next_key.kernel_stack_id == -EFAULT)
			goto print_ustack;

		if (bpf_map_lookup_elem(sfd, &next_key.kernel_stack_id, ip) != 0) {
			folded_printf(env.folded, "[Missed Kernel Stack]");
			goto print_ustack;
		}

		for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			const struct ksym *ksym = ksyms__map_addr(ksyms, ip[i]);

			if (!env.verbose) {
				folded_printf(env.folded, "%s", ksym ? ksym->name : "Unknown");
			} else {
				if (ksym)
					printf("    #%-2d 0x%lx %s+0x%lx\n", idx, ip[i], ksym->name, ip[i] - ksym->addr);
				else
					printf("    #%-2d 0x%lx [unknown]\n", idx, ip[i]);
				idx++;
			}
		}

print_ustack:
		if (next_key.user_stack_id == -1 || next_key.user_stack_id == -EFAULT)
			goto skip_ustack;

		if (bpf_map_lookup_elem(sfd, &next_key.user_stack_id, ip) != 0) {
			folded_printf(env.folded, "[Missing User Stack]");
			goto skip_ustack;
		}

		syms = syms_cache__get_syms(syms_cache, next_key.tgid);
		if (!syms) {
			if (!env.verbose) {
				warning("Failed to get sysms\n");
			} else {
				for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++)
					printf("    #%-2d 0x%016lx [unknown]\n", idx++, ip[i]);
			}
			goto skip_ustack;
		}

		for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			const struct sym *sym;

			if (!env.verbose) {
				sym = syms__map_addr(syms, ip[i]);
				folded_printf(env.folded, "%s", sym ? sym->name : "[unknown]");
			} else {
				char *dso_name;
				unsigned long dso_offset;

				sym = syms__map_addr_dso(syms, ip[i], &dso_name, &dso_offset);
				printf("    #%-2d 0x%016lx", idx++, ip[i]);
				if (sym)
					printf(" %s+0x%lx", sym->name, sym->offset);
				if (dso_name)
					printf(" (%s+0x%lx)", dso_name, dso_offset);
				printf("\n");
			}
		}

skip_ustack:
		if (!env.folded) {
			printf("    %-16s %s (%d)\n", "-", val.comm, next_key.pid);
			printf("        %lld\n\n", val.delta);
		} else {
			printf(" %lld\n", val.delta);
		}
	}

cleanup:
	free(ip);
}

static const char *stack_context(void)
{
	if (env.user_stacks_only)
		return "user";
	if (env.kernel_stacks_only)
		return "kernel";
	return "user + kernel";
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct syms_cache *syms_cache = NULL;
	struct ksyms *ksyms = NULL;
	struct offcputime_bpf *bpf_obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	if (env.user_threads_only && env.kernel_threads_only) {
		warning("user_threads_only and kernel_threads_only cann't be used together.\n");
		return 1;
	}

	if (env.user_stacks_only && env.kernel_stacks_only) {
		warning("user_stacks_only and kernel_stacks_only cann't be used together.\n");
		return 1;
	}

	if (env.min_block_time >= env.max_block_time) {
		warning("min_block_time should be smaller than max_block_time.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	bpf_obj = offcputime_bpf__open();
	if (!bpf_obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	/* Init global data (filtering options) */
	bpf_obj->rodata->target_tgid = env.pid;
	bpf_obj->rodata->target_pid = env.tid;
	bpf_obj->rodata->user_threads_only = env.user_threads_only;
	bpf_obj->rodata->user_stacks_only = env.user_stacks_only;
	bpf_obj->rodata->kernel_threads_only = env.kernel_threads_only;
	bpf_obj->rodata->kernel_stacks_only = env.kernel_stacks_only;
	bpf_obj->rodata->state = env.state;
	bpf_obj->rodata->min_block_ns = env.min_block_time;
	bpf_obj->rodata->max_block_ns = env.max_block_time;

	bpf_map__set_value_size(bpf_obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(bpf_obj->maps.stackmap, env.stack_storage_size);

	err = offcputime_bpf__load(bpf_obj);
	if (err) {
		warning("Failed to load BPF object\n");
		return 1;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("Failed to load kallsyms\n");
		goto cleanup;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		warning("Failed to create syms_cache\n");
		goto cleanup;
	}

	err = offcputime_bpf__attach(bpf_obj);
	if (err) {
		warning("Failed to attach BPF program\n");
		goto cleanup;
	}

	if (ksyms__get_symbol(ksyms, "finish_task_switch"))
		bpf_obj->links.oncpu = bpf_program__attach_kprobe(bpf_obj->progs.oncpu,
								  false,
								  "finish_task_switch");
	else if (ksyms__get_symbol(ksyms, "finish_task_switch.isra.0"))
		bpf_obj->links.oncpu = bpf_program__attach_kprobe(bpf_obj->progs.oncpu,
								  false,
								  "finish_task_switch.isra.0");
	if (!bpf_obj->links.oncpu) {
		warning("Failed to load attach finish_task_switch\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	if (!env.folded) {
		printf("Tracing off-CPU time (us) of all threads by %s stack", stack_context());
		if (env.duration < 99999999)
			printf(" for %d secs\n", env.duration);
		else
			printf("... Hit Ctrl-C to end.\n");
	}

	/*
	 * We'll get sleep interrupted when someone presses Ctrl-C (which will
	 * be "handled" with noop by sig_handler).
	 */
	sleep(env.duration);

	print_map(ksyms, syms_cache, bpf_obj);

cleanup:
	offcputime_bpf__destroy(bpf_obj);
	syms_cache__free(syms_cache);
	ksyms__free(ksyms);

	return err != 0;
}
