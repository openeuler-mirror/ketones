// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: wolfgang huang <huangjinhui@kylinos.cn>
//
// Based on profile.py - 2016 Brendan Gregg

#include "commons.h"
#include <linux/perf_event.h>
#include "profile.h"
#include "profile.skel.h"
#include "trace_helpers.h"
#include <sys/syscall.h>

static struct env {
	pid_t pid;
	pid_t tid;
	bool verbose;
	bool user_threads_only;
	bool kernel_threads_only;
	int stack_storage_size;
	int perf_max_stack_depth;
	int cpu;
	int frequency;
	int duration;
} env = {
	.pid = -1,
	.tid = -1,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.cpu = -1,
	.frequency = 49,
	.duration = 99999999,
};

const char *argp_program_version = "profile 0.1";
const char *argp_program_bug_address = "Wolfgang Huang <huangjinhui@kylinos.cn>";
const char argp_program_doc[] =
"Profile CPU usage by sampling stack traces at a timed interval\n"
"\n"
"USAGE: profile [--help] [-p PID | -L TID] [-U | -K] [-F FREQUENCY ]\n"
"		[--stack-storage-size STACK_STORAGE_SIZE]\n"
"		[--perf-max-stack-depth PREF_MAX_STACK_DEPTH]\n"
"		[-C CPU] [duration]\n\n"
"EXAMPLES:\n"
"	profile			# profile stack traces at 49 Hertz until Ctrl-C\n"
"	profile -F 99		# profile stack traces at 99 Hertz\n"
"	profile 5		# profile at 49 Hertz for 5 seconds only\n"
"	profile -p 185		# only profile process with PID 185\n"
"	profile -L 185		# only profile thread with TID 185\n"
"	profile -U		# only show user space stacks (no kernel)\n"
"	profile -K		# only show kernel space stacks (no user)\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "tid", 'L', "TID", 0, "Trace this TID only" },
	{ "user-threads-only", 'U', NULL, 0,
	  "User threads only (no kernel threads)" },
	{ "kernel-threads-only", 'K', NULL, 0,
	  "Kernel threads only (no user threads)" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "frequency", 'F', "FREQUENCY", 0, "sample frequency Hertz(default 49)" },
	{ "cpu", 'C', "CPU", 0, "cpu number to run profile(default -1)" },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)" },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)" },
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
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'L':
		env.tid = argp_parse_pid(key, arg, state);
		break;
	case 'U':
		env.user_threads_only = true;
		break;
	case 'K':
		env.kernel_threads_only = true;
		break;
	case 'F':
		env.frequency = argp_parse_long(key, arg, state);
		break;
	case 'C':
		env.cpu = argp_parse_long(key, arg, state);
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		env.perf_max_stack_depth = argp_parse_long(key, arg, state);
		break;
	case OPT_STACK_STORAGE_SIZE:
		env.stack_storage_size = argp_parse_long(key, arg, state);
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		env.duration = argp_parse_long(key, arg, state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
					struct bpf_link *links[])
{
	for (int i = 0; i < nr_cpus; i++) {
		struct perf_event_attr attr = {
			.type = PERF_TYPE_SOFTWARE,
			.freq = 1,
			.sample_period = freq,
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
			warning("Failed to attach perf event on cpu#%d!\n", i);
			close(fd);
			return -1;
		}
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

}

static void print_map(struct ksyms *ksyms, struct syms_cache *syms_cache,
			struct profile_bpf *bpf_obj)
{
	profile_key_t lookup_key = {}, next_key;
	int err, cfd, sfd;
	unsigned long *ip;
	__u64 val;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		warning("Failed to alloc ip\n");
		return;
	}

	cfd = bpf_map__fd(bpf_obj->maps.count);
	sfd = bpf_map__fd(bpf_obj->maps.stackmap);

	while (!bpf_map_get_next_key(cfd, &lookup_key, &next_key)) {
		int idx = 0, i;
		const struct syms *syms;

		lookup_key = next_key;

		err = bpf_map_lookup_elem(cfd, &next_key, &val);
		if (err < 0) {
			warning("Failed to lookup info: %d\n", err);
			goto cleanup;
		}

		if (bpf_map_lookup_elem(sfd, &next_key.kernel_stack_id, ip) != 0) {
			warning("    [Missed Kernel Stack]\n");
			goto print_ustack;
		}

		for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			const struct ksym *ksym = ksyms__map_addr(ksyms, ip[i]);

			if (!env.verbose) {
				printf("    %s%s\n", "b'", ksym ? ksym->name : "Unknown");
			} else {
				if (ksym)
					printf("    #%-2d 0x%lx %s+0x%lx\n", idx, ip[i], ksym->name, ip[i] - ksym->addr);
				else
					printf("    #%-2d 0x%lx [unknown]\n", idx, ip[i]);
				idx++;
			}
		}

		/* delete kernel stack map entry */
		bpf_map_delete_elem(sfd, &next_key.kernel_stack_id);
print_ustack:
		if (next_key.user_stack_id == -1)
			goto skip_ustack;

		if (bpf_map_lookup_elem(sfd, &next_key.user_stack_id, ip) != 0) {
			warning("     [Missing User Stack]\n");
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
			goto clean_ustack;
		}

		for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			const struct sym *sym;

			if (!env.verbose) {
				sym = syms__map_addr(syms, ip[i]);
				if (sym)
					printf("    %s\n", sym->name);
				else
					printf("    [unknown]\n");
			} else {
				char *dso_name;
				unsigned long dso_offset;

				sym = syms__map_addr_dso(syms, ip[i], &dso_name, &dso_offset);
				printf("    #%-2d 0x%016lx", idx++, ip[i]);
				if (sym) {
					printf(" %s+0x%lx", sym->name, sym->offset);
					if (dso_name)
						printf(" (%s+0x%lx)", dso_name, dso_offset);
				}
				printf("\n");
			}
		}

clean_ustack:
		/* delete for userstack map entry */
		bpf_map_delete_elem(sfd, &next_key.user_stack_id);
skip_ustack:
		printf("    %-16s %s (%d)\n", "-", next_key.comm, next_key.pid);
		printf("        %lld\n\n", val);

		/* delete profile_key entry */
		bpf_map_delete_elem(cfd, &next_key);
	}
cleanup:
	free(ip);
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct bpf_link *links[MAX_CPU_NR] = {};
	struct syms_cache *syms_cache = NULL;
	struct ksyms *ksyms = NULL;
	struct profile_bpf *bpf_obj;
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

	libbpf_set_print(libbpf_print_fn);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		warning("Failed to get # of possible cpus: '%s'!\n",
			strerror(-nr_cpus));
		return 1;
	}

	if (nr_cpus > MAX_CPU_NR) {
		warning("the number of cpu cores is too big, please "
			"increase MAX_CPU_NR's value and recompile");
		return 1;
	}

	bpf_obj = profile_bpf__open();
	if (!bpf_obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	/* Init global data (filtering options) */
	bpf_obj->rodata->target_tgid = env.pid;
	bpf_obj->rodata->target_pid = env.tid;
	bpf_obj->rodata->user_threads_only = env.user_threads_only;
	bpf_obj->rodata->kernel_threads_only = env.kernel_threads_only;

	bpf_map__set_value_size(bpf_obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(bpf_obj->maps.stackmap, env.stack_storage_size);


	err = profile_bpf__load(bpf_obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
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

	err = open_and_attach_perf_event(env.frequency, bpf_obj->progs.profile_event_sample, links);
	if (err) {
		warning("Failed to attach perf event\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	/*
	 * We'll get sleep interrupted when someone presses Ctrl-C (which will
	 * be "handled" with noop by sig_handler).
	 */
	sleep(env.duration);

	print_map(ksyms, syms_cache, bpf_obj);
cleanup:
	/* cleanup bpf link to detach & free */
	for (int i = 0; i < nr_cpus; i++)
		bpf_link__destroy(links[i]);
	profile_bpf__destroy(bpf_obj);
	syms_cache__free(syms_cache);
	ksyms__free(ksyms);

	return err;
}
