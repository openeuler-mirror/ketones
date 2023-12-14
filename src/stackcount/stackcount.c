// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// WARNING: This program can only be run on kernels that support kprobe multi.
// If it is not supported, it will exit directly. Currently, on X86, at least
// the kernel must be greater than v5.18-rc1 and Config must be enable
// CONFIG_FPROBE, currently not supported on other platforms.
//
// Base on stackcount.py - Brendan Gregg

#include "commons.h"
#include "stackcount.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"
#include "map_helpers.h"
#include "stackcount.h"

static struct ksyms *ksyms;
static struct syms_cache *syms_cache;
static volatile sig_atomic_t exiting;

enum TRACE_TYPE {
	KPROBE,
	UPROBE,
	TRACEPOINT,
	USDT,
};

static struct env {
	bool verbose;
	int interval;
	int interations;
	int duration;
	pid_t pid;
	bool timestamp;
	int cpu;
	bool offset;
	bool per_pid;
	bool need_kernel_stack;
	bool need_user_stack;
	bool delimiter;
	bool use_regex;
	int stack_storage_size;
	int perf_max_stack_depth;
	const char *functions;
} env = {
	.interval = 99999999,
	.interations = 99999999,
	.cpu = -1,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.need_kernel_stack = true,
	.need_user_stack = true,
};

const char *argp_program_version = "stackcount 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"stackcount    Count events and their stack traces.\n"
"\n"
"USAGE: stackcount.py [-h] [-p PID] [-c CPU] [-i INTERVAL] [-D DURATION] [-T]\n"
"                     [-s] [-P] [-K] [-U] [-v]\n"
"\n"
"Example:\n"
"    stackcount submit_bio         # count kernel stack traces for submit_bio\n"
"    stackcount -d ip_output       # include a user/kernel stack delimiter\n"
"    stackcount -s ip_output       # show symbol offsets\n"
"    stackcount -sv ip_output      # show offsets and raw addresses (verbose)\n"
"    stackcount 'tcp_send*'        # count stacks for funcs matching tcp_send*\n"
"    stackcount -r '^tcp_send.*'   # same as above, using regular expressions\n"
"    stackcount -Ti 5 ip_output    # output every 5 seconds, with timestamps\n"
"    stackcount -p 185 ip_output   # count ip_output stacks for PID 185 only\n"
"    stackcount -c 1 put_prev_entity   # count put_prev_entity stacks for CPU 1 only\n"
"    stackcount -p 185 c:malloc    # count stacks for malloc in PID 185\n"
"    stackcount t:sched:sched_switch # count stacks for sched_switch tracepoint\n"
"    stackcount -K t:sched:sched_switch   # kernel stacks only\n"
"    stackcount -U t:sched:sched_switch   # user stacks only\n";

#define OPT_PERF_MAX_STACK_DEPTH	1	/* for --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2	/* for --stack-storage-size */

static struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "interval", 'i', "INTERVAL", 0, "Output interval, in seconds" },
	{ "pid", 'p', "PID", 0, "Trace process PID only" },
	{ "cpu", 'c', "CPU", 0, "Trace this CPU only" },
	{ "regex", 'r', NULL, 0, "use regular expressions" },
	{ "duration", 'D', "DURATION", 0, "Total duration of trace, seconds" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "offset", 's', NULL, 0, "Show address offsets" },
	{ "perpid", 'P', NULL, 0, "Display stacks separately for each process" },
	{ "delimited", 'd', NULL, 0, "insert delimiter between kernel/user stacks" },
	{ "kernel-stacks-only", 'K', NULL, 0, "kernel stack only" },
	{ "user-stacks-only", 'U', NULL, 0, "user stack only" },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default: 127)" },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default: 1024)" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
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
	case 'c':
		env.cpu = argp_parse_long(key, arg, state);
		break;
	case 'p':
		env.pid = argp_parse_long(key, arg, state);
		break;
	case 's':
		env.offset = true;
		break;
	case 'd':
		env.delimiter = true;
		break;
	case 'r':
		env.use_regex = true;
		break;
	case 'D':
		env.duration = argp_parse_long(key, arg, state);
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'P':
		env.per_pid = true;
		break;
	case 'K':
		env.need_kernel_stack = true;
		env.need_user_stack = false;
		break;
	case 'U':
		env.need_user_stack = true;
		env.need_kernel_stack = false;
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		env.perf_max_stack_depth = argp_parse_long(key, arg, state);
		break;
	case OPT_STACK_STORAGE_SIZE:
		env.stack_storage_size = argp_parse_long(key, arg, state);
		break;
	case ARGP_KEY_END:
		if (env.duration) {
			env.interval = min(env.interval, env.duration);
			env.interations = env.duration / env.interval;
		}
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num != 0) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		env.functions = arg;
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

static int split_pattern(const char *raw_pattern, enum TRACE_TYPE *type,
			 const char **library, const char **pattern)
{
	const char *string1, *string2, *string3;
	char *raw_pattern_tmp = strdup(raw_pattern);

	string1 = strsep(&raw_pattern_tmp, ":");
	if (!raw_pattern_tmp) {
		/* Not found ':', return raw_pattern */
		*type = KPROBE;
		*pattern = raw_pattern;
		return 0;
	}

	string2 = strsep(&raw_pattern_tmp, ":");
	if (!raw_pattern_tmp) {
		/* One ':' found, return library */
		*type = UPROBE;
		*library = string1;
		*pattern = string2;
		return 0;
	}

	string3 = strsep(&raw_pattern_tmp, ":");
	if (strlen(string1) != 1)
		return -EINVAL;
	if (string1[0] == 'u')
		*type = USDT;
	else if (string1[0] == 't')
		*type = TRACEPOINT;
	else if (string1[0] == 'p') {
		if (strlen(string2) == 0)
			*type = KPROBE;
		else
			*type = UPROBE;
	} else
		return -EINVAL;

	if (*type != KPROBE)
		*library = string2;
	*pattern = string3;

	return 0;
}

struct value {
	struct key_t key;
	struct value_t val;
};

static void print_stack_counts(struct stackcount_bpf *obj, const struct value *value)
{
	unsigned long *ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	struct key_t key = value->key;
	const struct syms *syms;

	if (!env.need_kernel_stack)
		goto print_ustack;

	if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.stacks),
				&key.kernel_stack_id, ip))
		goto print_ustack;
	for (int i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
		const struct ksym *ksym = ksyms__map_addr(ksyms, ip[i]);
		char buf[1024];

		if (ksym) {
			if (env.offset)
				sprintf(buf, "%s+0x%lx", ksym->name, ip[i] - ksym->addr);
			else
				sprintf(buf, "%s", ksym->name);
		}
		printf("  b'%s'\n", ksym ? buf : "Unknown");
	}

print_ustack:
	if (!env.need_user_stack || key.user_stack_id == -1 ||
	    key.pid == 0xffffffff)
		goto skip_ustack;

	if (env.delimiter && env.need_kernel_stack)
		printf("    --\n");

	if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.stacks),
				&key.user_stack_id, ip))
		goto skip_ustack;
	syms = syms_cache__get_syms(syms_cache, key.pid);
	if (!syms) {
		warning("Failed to get syms\n");
		goto skip_ustack;
	}

	for (int i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
		const struct sym *sym = syms__map_addr(syms, ip[i]);
		char buf[1024];

		if (sym) {
			if (env.offset)
				sprintf(buf, "%s+0x%lx",
					demangling_cplusplus_function(sym->name),
					sym->offset);
			else
				sprintf(buf, "%s",
					demangling_cplusplus_function(sym->name));
		}
		printf("  b'%s'\n", sym ? buf : "Unknown");
	}

skip_ustack:
	if (key.pid != 0xffffffff && !env.pid)
		printf("    b'%s' [%d] - CPU#%d\n", key.name, key.pid,
		       value->val.cpu);

	printf("    %lld\n\n", value->val.count);
	free(ip);
}

static int sort_column(const void *o1, const void *o2)
{
	const struct value *v1 = o1;
	const struct value *v2 = o2;

	return v1->val.count - v2->val.count;
}

static int dump_stack_maps(int fd, struct value values[])
{
	struct key_t key = {}, next_key;
	int err = 0, rows = 0;

	while (!bpf_map_get_next_key(fd, &key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &values[rows].val);
		if (err < 0) {
			warning("bpf_map_lookup_elem failed\n");
			return err;
		}
		key = values[rows++].key = next_key;
	}

	memset(&key, 0, sizeof(struct key_t));
	while (!bpf_map_get_next_key(fd, &key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			warning("Failed to cleanup info: %d\n", err);
			return err;
		}
		key = next_key;
	}

	qsort(values, rows, sizeof(struct value), sort_column);
	return rows;
}

static void print_maps(struct stackcount_bpf *obj)
{
	static struct value values[MAX_ENTRIES];
	int fd = bpf_map__fd(obj->maps.counts);
	int rows;

	rows = dump_stack_maps(fd, values);
	if (rows < 0) {
		warning("Dump hash: %d\n", rows);
		return;
	}

	for (int i = 0; i < rows; i++)
		print_stack_counts(obj, &values[i]);
}

static int attach_kprobe(struct stackcount_bpf *obj,
			 const char *pattern,
			 struct bpf_kprobe_multi_opts *kmopts)
{
	kmopts->use_regex = env.use_regex;
	obj->links.function_entry =
		bpf_program__attach_kprobe_multi_opts(obj->progs.function_entry,
						      pattern, kmopts);
	if (!obj->links.function_entry) {
		warning("Failed to attach kprobe multi, kernel don't support: %s\n",
			strerror(errno));
		return -errno;
	}
	return 0;
}

static int attach_tracepoint(struct stackcount_bpf *obj, const char *library,
			     const char *pattern)
{
	obj->links.tracepoint_entry =
		bpf_program__attach_tracepoint(obj->progs.tracepoint_entry,
					       library, pattern);
	if (!obj->links.tracepoint_entry) {
		warning("Failed to attach t:%s:%s\n", library, pattern);
		return -errno;
	}
	return 0;
}

static int attach_uprobe(struct stackcount_bpf *obj, const char *binary,
			 const char *function)
{
	int pid = env.pid;
	char bin_path[PATH_MAX];
	off_t func_off;

	if (pid == 0)
		pid = getpid();

	if (resolve_binary_path(binary, pid, bin_path, sizeof(bin_path)))
		return 1;

	func_off = get_elf_func_offset(bin_path, function);
	if (func_off < 0) {
		warning("Could not find %s in %s\n", function, bin_path);
		return 1;
	}

	obj->links.function_uprobe_entry =
		bpf_program__attach_uprobe(obj->progs.function_uprobe_entry,
					   false, env.pid ?: -1, bin_path, func_off);
	if (!obj->links.function_uprobe_entry) {
		warning("Failed to attach uprobe: %d\n", -errno);
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_kprobe_multi_opts, kmopts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct stackcount_bpf *obj;
	enum TRACE_TYPE type;
	const char *library, *pattern;
	int err, cnt;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!env.functions) {
		warning("Not set functions to trace.\n");
		return 1;
	}

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = stackcount_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = env.pid;
	obj->rodata->target_cpu = env.cpu;
	obj->rodata->need_kernel_stack = env.need_kernel_stack;
	obj->rodata->need_user_stack = env.need_user_stack;
	obj->rodata->target_per_pid = env.per_pid;
	bpf_map__set_value_size(obj->maps.stacks,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stacks, env.stack_storage_size);

	if (env.use_regex) {
		pattern = env.functions;
		type = KPROBE;
	} else {
		split_pattern(env.functions, &type, &library, &pattern);
	}

	switch (type) {
	case USDT:
		bpf_program__set_autoload(obj->progs.function_uprobe_entry, false);
		bpf_program__set_autoload(obj->progs.function_entry, false);
		bpf_program__set_autoload(obj->progs.tracepoint_entry, false);
		env.need_kernel_stack = obj->rodata->need_kernel_stack = false;
		warning("Not implement uprobe/USDT\n");
		goto cleanup;
	case UPROBE:
		bpf_program__set_autoload(obj->progs.function_entry, false);
		bpf_program__set_autoload(obj->progs.tracepoint_entry, false);
		env.need_kernel_stack = obj->rodata->need_kernel_stack = false;
		break;
	case KPROBE:
		bpf_program__set_autoload(obj->progs.tracepoint_entry, false);
		bpf_program__set_autoload(obj->progs.function_uprobe_entry, false);
		break;
	case TRACEPOINT:
		bpf_program__set_autoload(obj->progs.function_entry, false);
		bpf_program__set_autoload(obj->progs.function_uprobe_entry, false);
		break;
	default:
		warning("Wrong trace type, exiting\n");
		goto cleanup;
	}

	err = stackcount_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	switch (type) {
	case KPROBE:
		err = attach_kprobe(obj, pattern, &kmopts);
		if (err)
			goto cleanup;
		cnt = kmopts.cnt;
		break;
	case TRACEPOINT:
		err = attach_tracepoint(obj, library, pattern);
		if (err)
			goto cleanup;
		cnt = 1;
		break;
	case UPROBE:
		err = attach_uprobe(obj, library, pattern);
		if (err)
			goto cleanup;
		cnt = 1;
		break;
	default:
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("Failed to load ksyms\n");
		err = 1;
		goto cleanup;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		warning("Failed to create syms_cache\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		err = 1;
		warning("Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Tracing %d functions... Ctrl-C to end.\n", cnt);
	for (int i = 0; i < env.interations && !exiting; i++) {
		sleep(env.interval);

		printf("\n");
		if (env.timestamp) {
			char ts[32];

			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s\n", ts);
		}

		print_maps(obj);
	}
	printf("Detaching...\n");

cleanup:
	stackcount_bpf__destroy(obj);
	ksyms__free(ksyms);
	syms_cache__free(syms_cache);

	return err != 0;
}
