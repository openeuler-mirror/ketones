// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Base on trace.py - Copyright (C) 2016 Sasha Goldshtein.

#include "commons.h"
#include "trace.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"
#include "map_helpers.h"
#include "trace.h"

static struct ksyms *ksyms;
static struct syms_cache *syms_cache;
static volatile sig_atomic_t exiting;
static struct expr_array *expr_array;
static bool has_expr_array;
static char format_str[100];
static char condition_str[50];

extern int libbpf_ensure_mem(void **data, size_t *cap_cnt, size_t elem_sz, size_t need_cnt);

enum aliases_type {
	ARG1_TYPE,
	ARG2_TYPE,
	ARG3_TYPE,
	ARG4_TYPE,
	ARG5_TYPE,
	ARG6_TYPE,
	RETVAL_TYPE,
	UID_TYPE,
	GID_TYPE,
	PID_TYPE,
	TID_TYPE,
	CPU_TYPE,
	TASK_TYPE,
	MAX_ATYPE_NUMS,
};

enum predicate {
	PREDICATE_EQ,
	PREDICATE_NE,
	PREDICATE_GE,
	PREDICATE_GT,
	PREDICATE_LE,
	PREDICATE_LT,
};

static struct env {
	bool verbose;
	bool print_cpu;
	pid_t pid;
	pid_t tid;
	bool timestamp;
	bool need_kernel_stack;
	bool need_user_stack;
	int stack_storage_size;
	int perf_max_stack_depth;
	const char *expr;
} env = {
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
};

const char *argp_program_version = "trace 0.1";
const char *argp_program_bug_address = "Youling Tang <tangyouling@kylinos.cn>";
const char argp_program_doc[] =
"trace    Trace a function and print a trace message based on its\n"
"         parameters, with an optional filter.\n"
"\n"
"USAGE: trace [-h] [-p PID] [-L TID] [-v] [-T] [-K] [-U] [-C]\n"
"             probe [probe ...]\n"
"\n"
"Example:\n"
"trace do_sys_open\n"
"        Trace the open syscall and print a default trace message when\n"
"        entered\n"
"trace 'sys_read (arg3 > 20000) \"read %d bytes\", arg3'\n"
"        Trace the read syscall and print a message for reads >20000 bytes\n"
"trace 'do_sys_open \"%llx\", retval'\n"
"        Trace the return from the open syscall and print the return value\n"
"trace 'c:open (arg2 == 42) \"%s %d\", arg1, arg2'\n"
"        Trace the open() call from libc only if the flags (arg2) argument is\n"
"        42\n"
"trace 'c:malloc \"size = %d\", arg1'\n"
"        Trace malloc calls and print the size being allocated\n"
"trace 'c:malloc (retval) \"allocated = %x\", retval'\n"
"        Trace returns from malloc and print non-NULL allocated buffers\n"
"trace 'p:c:write (arg1 == 1) \"writing %d bytes to STDOUT\", arg3'\n"
"        Trace the write() call from libc to monitor writes to STDOUT\n"
"trace 't:block:block_rq_complete'\n"
"        Trace the block_rq_complete kernel tracepoint\n"
"trace 't:block:block_rq_complete -K'\n"
"        Trace the block_rq_complete kernel tracepoint and print kernel stack\n";

#define OPT_PERF_MAX_STACK_DEPTH	1	/* for --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2	/* for --stack-storage-size */

static struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "print_cpu", 'C', NULL, 0, "print CPU id", 0 },
	{ "pid", 'p', "PID", 0, "id of the process to trace (optional)", 0 },
	{ "tid", 'L', "TID", 0, "id of the thread to trace (optional)", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "kernel-stacks-only", 'K', NULL, 0, "kernel stack only", 0 },
	{ "user-stacks-only", 'U', NULL, 0, "user stack only", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default: 127)", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default: 1024)", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help", 0 },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'C':
		env.print_cpu = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'L':
		env.tid = argp_parse_pid(key, arg, state);
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'K':
		env.need_kernel_stack = true;
		break;
	case 'U':
		env.need_user_stack = true;
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		env.perf_max_stack_depth = argp_parse_long(key, arg, state);
		break;
	case OPT_STACK_STORAGE_SIZE:
		env.stack_storage_size = argp_parse_long(key, arg, state);
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num != 0) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		env.expr = arg;
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

struct condition {
	enum aliases_type atype;
	enum predicate pred;
	__u64 val;
	bool single;
};

struct expr_array {
	size_t nr;
	size_t capacity;
	struct condition cond;
	enum aliases_type *atype;
};

static int alloc_expr_array(struct expr_array *expr_array)
{

	return libbpf_ensure_mem((void **)&expr_array->atype, &expr_array->capacity,
				 sizeof(*expr_array->atype), expr_array->nr + 1);
}

static void free_expr_array(struct expr_array *expr_array)
{
	free(expr_array->atype);
	free(expr_array);
}

static void match_atype(char * token, struct expr_array *expr_array, bool to_atype)
{
	int type = -1;

	if (strstr(token, "arg1"))
		type = ARG1_TYPE;
	else if (strstr(token, "arg2"))
		type = ARG2_TYPE;
	else if (strstr(token, "arg3"))
		type = ARG3_TYPE;
	else if (strstr(token, "arg4"))
		type = ARG4_TYPE;
	else if (strstr(token, "arg5"))
		type = ARG5_TYPE;
	else if (strstr(token, "arg6"))
		type = ARG6_TYPE;
	else if (strstr(token, "retval"))
		type = RETVAL_TYPE;
	else if (strstr(token, "$uid"))
		type = UID_TYPE;
	else if (strstr(token, "$gid"))
		type = GID_TYPE;
	else if (strstr(token, "$pid"))
		type = PID_TYPE;
	else if (strstr(token, "$tgid"))
		type = TID_TYPE;
	else if (strstr(token, "$cpu"))
		type = CPU_TYPE;
	else if (strstr(token, "$task"))
		type = TASK_TYPE;

	if (type == -1)
		return;

	if (to_atype)
		expr_array->atype[expr_array->nr++] = type;
	else
		expr_array->cond.atype = type;
}

static __u64 print_atype(struct key_t *key, enum aliases_type atype)
{
	switch (atype) {
	case ARG1_TYPE:
	case ARG2_TYPE:
	case ARG3_TYPE:
	case ARG4_TYPE:
	case ARG5_TYPE:
	case ARG6_TYPE:
		return key->args[atype];
	case RETVAL_TYPE:
		return key->retval;
	case UID_TYPE:
		return (__u64)key->uid;
	case GID_TYPE:
		return (__u64)key->gid;
	case PID_TYPE:
		return (__u64)key->pid;
	case TID_TYPE:
		return (__u64)key->tid;
	case CPU_TYPE:
		return (__u64)key->cpu;
	case TASK_TYPE:
		return (__u64)key->task;
	default:
		return 0;
	}
}

static void print_expr(struct key_t *key, struct expr_array *expr_array)
{
	if (expr_array->nr > MAX_ATYPE_NUMS)
		warning("Too many atype nums are printed.\n");

	switch (expr_array->nr) {
	case 1:
		printf(format_str, print_atype(key, expr_array->atype[0]));
		break;
	case 2:
		printf(format_str, print_atype(key, expr_array->atype[0]),
			print_atype(key, expr_array->atype[1]));
		break;
	case 3:
		printf(format_str, print_atype(key, expr_array->atype[0]),
			print_atype(key, expr_array->atype[1]),
			print_atype(key, expr_array->atype[2]));
		break;
	case 4:
		printf(format_str, print_atype(key, expr_array->atype[0]),
			print_atype(key, expr_array->atype[1]),
			print_atype(key, expr_array->atype[2]),
			print_atype(key, expr_array->atype[3]));
		break;
	case 5:
		printf(format_str, print_atype(key, expr_array->atype[0]),
			print_atype(key, expr_array->atype[1]),
			print_atype(key, expr_array->atype[2]),
			print_atype(key, expr_array->atype[3]),
			print_atype(key, expr_array->atype[4]));
		break;
	case 6:
		printf(format_str, print_atype(key, expr_array->atype[0]),
			print_atype(key, expr_array->atype[1]),
			print_atype(key, expr_array->atype[2]),
			print_atype(key, expr_array->atype[3]),
			print_atype(key, expr_array->atype[4]),
			print_atype(key, expr_array->atype[5]));
		break;
	case 7:
		printf(format_str, print_atype(key, expr_array->atype[0]),
			print_atype(key, expr_array->atype[1]),
			print_atype(key, expr_array->atype[2]),
			print_atype(key, expr_array->atype[3]),
			print_atype(key, expr_array->atype[4]),
			print_atype(key, expr_array->atype[5]),
			print_atype(key, expr_array->atype[6]));
		break;
	case 8:
		printf(format_str, print_atype(key, expr_array->atype[0]),
			print_atype(key, expr_array->atype[1]),
			print_atype(key, expr_array->atype[2]),
			print_atype(key, expr_array->atype[3]),
			print_atype(key, expr_array->atype[4]),
			print_atype(key, expr_array->atype[5]),
			print_atype(key, expr_array->atype[6]),
			print_atype(key, expr_array->atype[7]));
		break;
	case 9:
		printf(format_str, print_atype(key, expr_array->atype[0]),
			print_atype(key, expr_array->atype[1]),
			print_atype(key, expr_array->atype[2]),
			print_atype(key, expr_array->atype[3]),
			print_atype(key, expr_array->atype[4]),
			print_atype(key, expr_array->atype[5]),
			print_atype(key, expr_array->atype[6]),
			print_atype(key, expr_array->atype[7]),
			print_atype(key, expr_array->atype[8]));
		break;
	case 10:
		printf(format_str, print_atype(key, expr_array->atype[0]),
			print_atype(key, expr_array->atype[1]),
			print_atype(key, expr_array->atype[2]),
			print_atype(key, expr_array->atype[3]),
			print_atype(key, expr_array->atype[4]),
			print_atype(key, expr_array->atype[5]),
			print_atype(key, expr_array->atype[6]),
			print_atype(key, expr_array->atype[7]),
			print_atype(key, expr_array->atype[8]),
			print_atype(key, expr_array->atype[9]));
		break;
	case 11:
		printf(format_str, print_atype(key, expr_array->atype[0]),
			print_atype(key, expr_array->atype[1]),
			print_atype(key, expr_array->atype[2]),
			print_atype(key, expr_array->atype[3]),
			print_atype(key, expr_array->atype[4]),
			print_atype(key, expr_array->atype[5]),
			print_atype(key, expr_array->atype[6]),
			print_atype(key, expr_array->atype[7]),
			print_atype(key, expr_array->atype[8]),
			print_atype(key, expr_array->atype[9]),
			print_atype(key, expr_array->atype[10]));
		break;
	case 12:
		printf(format_str, print_atype(key, expr_array->atype[0]),
			print_atype(key, expr_array->atype[1]),
			print_atype(key, expr_array->atype[2]),
			print_atype(key, expr_array->atype[3]),
			print_atype(key, expr_array->atype[4]),
			print_atype(key, expr_array->atype[5]),
			print_atype(key, expr_array->atype[6]),
			print_atype(key, expr_array->atype[7]),
			print_atype(key, expr_array->atype[8]),
			print_atype(key, expr_array->atype[9]),
			print_atype(key, expr_array->atype[10]),
			print_atype(key, expr_array->atype[11]));
		break;
	case 13:
		printf(format_str, print_atype(key, expr_array->atype[0]),
			print_atype(key, expr_array->atype[1]),
			print_atype(key, expr_array->atype[2]),
			print_atype(key, expr_array->atype[3]),
			print_atype(key, expr_array->atype[4]),
			print_atype(key, expr_array->atype[5]),
			print_atype(key, expr_array->atype[6]),
			print_atype(key, expr_array->atype[7]),
			print_atype(key, expr_array->atype[8]),
			print_atype(key, expr_array->atype[9]),
			print_atype(key, expr_array->atype[10]),
			print_atype(key, expr_array->atype[11]),
			print_atype(key, expr_array->atype[12]));
		break;
	}
}

static void match_pred(char *pred, struct expr_array *expr_array)
{
	if (!strcmp(pred, "=="))
		expr_array->cond.pred = PREDICATE_EQ;
	else if (!strcmp(pred, "!="))
		expr_array->cond.pred = PREDICATE_NE;
	else if (!strcmp(pred, ">="))
		expr_array->cond.pred = PREDICATE_GE;
	else if (!strcmp(pred, ">"))
		expr_array->cond.pred = PREDICATE_GT;
	else if (!strcmp(pred, "<="))
		expr_array->cond.pred = PREDICATE_LE;
	else if (!strcmp(pred, "<"))
		expr_array->cond.pred = PREDICATE_LT;
	else
		warning("Unknown PREDICATE_*.\n");
}

static void parse_condition(char *expr, struct expr_array *expr_array)
{
	char *start = NULL, *end = NULL;
	char pred[50], pred2[50];
	__u64 v;

	start = strchr(expr, '(');
	end = strrchr(expr, ')');
	if(!start || !end || end == start + 1)
		return;

	strncpy(condition_str, start + 1, (unsigned long)(end - start - 1));

	/* like (retval) */
	if (!strstr(condition_str, " ")) {
		match_atype(condition_str, expr_array, false);
		expr_array->cond.single = true;
		return;
	}

	/* like (retval != 0) */
	if (sscanf(condition_str, "%s %[!=><]%lli", pred, pred2, &v) != 3) {
		warning("Invalid specification; expected predicate, not '%s'\n",
			condition_str);
		return;
	}

	match_atype(pred, expr_array, false);
	match_pred(pred2, expr_array);
	expr_array->cond.val = v;
	expr_array->cond.single = false;
}

static bool handle_condition(struct key_t *key, struct expr_array *expr_array)
{
	__u64 left;

	if (!expr_array || condition_str[0] == ' ')
		return true;

	left = print_atype(key, expr_array->cond.atype);

	if (expr_array->cond.single) {
		if (left)
			return true;
		else
			return false;
	}

	switch (expr_array->cond.pred) {
	case PREDICATE_EQ:
		if (left == expr_array->cond.val)
			return true;
		break;
	case PREDICATE_NE:
		if (left != expr_array->cond.val)
			return true;
		break;
	case PREDICATE_GE:
		if (left >= expr_array->cond.val)
			return true;
		break;
	case PREDICATE_GT:
		if (left > expr_array->cond.val)
			return true;
		break;
	case PREDICATE_LE:
		if (left <= expr_array->cond.val)
			return true;
		break;
	case PREDICATE_LT:
		if (left < expr_array->cond.val)
			return true;
		break;
	}

	return false;
}

static char *parse_expr(const char *expr)
{
	int err;
	char *expr_tmp, *token, *function;
	char *start, *end;

	expr_tmp = strdup(expr);
	function = strsep(&expr_tmp, " ");

	if (!expr_tmp)
		return function;

	start = strchr(expr_tmp, '\"');
	end = strrchr(expr_tmp, '\"');
	strncpy(format_str, start + 1, (unsigned long)(end - start - 1));

	expr_array = calloc(1, sizeof(*expr_array));
	if (!expr_array)
		return NULL;

	parse_condition(expr_tmp, expr_array);

	expr_tmp = expr_tmp + (unsigned long)(end - expr_tmp + 1);
	while ((token = strsep(&expr_tmp, ",")) != NULL) {
		err = alloc_expr_array(expr_array);
		if (err)
			goto free_expr_array;

		match_atype(token, expr_array, true);
	}
	has_expr_array = true;

	return function;

free_expr_array:
	free_expr_array(expr_array);
	return NULL;
}

static void print_stack_counts(struct trace_bpf *obj, const struct value *value)
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
		if (!ksym)
			printf("    b'Unknown [kernel]'");
		else
			printf("    b'%s+0x%lx [kernel]'\n", ksym->name, ip[i] - ksym->addr);
	}

print_ustack:
	if (!env.need_user_stack || key.user_stack_id == -1 ||
	    key.pid == 0xffffffff)
		goto skip_ustack;

	if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.stacks),
				&key.user_stack_id, ip))
		goto skip_ustack;
	syms = syms_cache__get_syms(syms_cache, key.pid);
	if (!syms) {
		warning("Failed to get syms\n");
		goto skip_ustack;
	}

	for (int i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
		struct sym_info sinfo;
		int err;

		err = syms__map_addr_dso(syms, ip[i], &sinfo);
		if (err != 0) {
			printf("    b'Unknown'\n");
		} else {
			printf("    b'%s+0x%lx'", demangling_cplusplus_function(sinfo.sym_name),
					sinfo.sym_offset);
			if (sinfo.dso_name)
				printf(" (%s+0x%lx)", sinfo.dso_name, sinfo.dso_offset);
			printf("\n");
		}

	}

skip_ustack:
	printf("      %lld\n", value->val.count);
	printf("\n");

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

static void print_maps(struct trace_bpf *obj, const char *pattern)
{
	static struct value values[MAX_ENTRIES];
	int fd = bpf_map__fd(obj->maps.counts);
	int rows;

	rows = dump_stack_maps(fd, values);
	if (rows < 0) {
		warning("Dump hash: %d\n", rows);
		return;
	}

	for (int i = 0; i < rows; i++) {
		struct key_t key = (&values[i])->key;

		if (!handle_condition(&key, expr_array))
			continue;

		if (env.timestamp) {
			char ts[32];

			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s ", ts);
		}

		if (env.print_cpu)
			printf("%-3d ", key.cpu);
		printf("%-7d %-7d %-15s %-16s ", key.pid, key.tid, key.comm, pattern);
		if (has_expr_array)
			print_expr(&key, expr_array);
		printf("\n");

		if (env.need_kernel_stack || env.need_user_stack)
			print_stack_counts(obj, &values[i]);
	}
}

static int attach_kprobe(struct trace_bpf *obj,
			 const char *pattern,
			 struct bpf_kprobe_opts *kmopts)
{
	obj->links.function_entry =
		bpf_program__attach_kprobe_opts(obj->progs.function_entry,
						      pattern, kmopts);
	if (!obj->links.function_entry) {
		warning("Failed to attach kprobe multi, kernel don't support: %s\n",
			strerror(errno));
		return -errno;
	}
	return 0;
}

static int attach_tracepoint(struct trace_bpf *obj, const char *library,
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

static int attach_uprobe(struct trace_bpf *obj, const char *binary,
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
	LIBBPF_OPTS(bpf_kprobe_opts, kmopts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct trace_bpf *obj;
	enum TRACE_TYPE type;
	const char *library, *pattern;
	char *function;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!env.expr) {
		warning("Not set functions to trace.\n");
		return 1;
	}

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = trace_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = env.pid;
	obj->rodata->target_pid = env.tid;
	obj->rodata->need_kernel_stack = env.need_kernel_stack;
	obj->rodata->need_user_stack = env.need_user_stack;
	bpf_map__set_value_size(obj->maps.stacks,
				env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stacks, env.stack_storage_size);

	function = parse_expr(env.expr);
	if (!function) {
		warning("Parse expr failed!\n");
		goto cleanup;
	}
	split_pattern(function, &type, &library, &pattern);

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

	err = trace_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	switch (type) {
	case KPROBE:
		err = attach_kprobe(obj, pattern, &kmopts);
		if (err)
			goto cleanup;
		break;
	case TRACEPOINT:
		err = attach_tracepoint(obj, library, pattern);
		if (err)
			goto cleanup;
		break;
	case UPROBE:
		err = attach_uprobe(obj, library, pattern);
		if (err)
			goto cleanup;
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

	if (env.timestamp)
		printf("%-8s ", "TIME");
	if (env.print_cpu)
		printf("%-3s ", "CPU");
	printf("%-7s %-7s %-15s %-16s %s\n", "PID", "TID", "COMM", "FUNC", "-");

	/* Loop */
	while(!exiting)
		print_maps(obj, pattern);

cleanup:
	if (has_expr_array)
		free_expr_array(expr_array);
	trace_bpf__destroy(obj);
	ksyms__free(ksyms);
	syms_cache__free(syms_cache);

	return err != 0;
}
