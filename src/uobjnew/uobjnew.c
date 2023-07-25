// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include <stdio.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <string.h>

#include "uobjnew.skel.h"
#include "compat.h"
#include "uobjnew.h"
#include "uprobe_helpers.h"
#include "btf_helpers.h"

#define LIB_FILE_PATH_BUFF_SIZE   256

static volatile sig_atomic_t exiting;

static struct env {
	pid_t pid;
	bool verbose;
	int top_count;
	int top_size;
	enum lang language;
	time_t interval;
} env = {
	.interval = 99999999,
};

struct alloc_entry {
	struct key_t key;
	struct val_t val;
};

const char *argp_program_version = "uobjnew 0.1";
const char *argp_program_bug_address = "chenyuan <chenyuan@kylinos.cn>";
const char argp_program_doc[] =
"Summarize object allocations in high-level languages.\n"
"\n"
"USAGE: uobjnew [-h] [-l {c,java,ruby,tcl}] [-C TOP_COUNT] [-S TOP_SIZE] [-v] [-p pid] [interval]\n"
"\n"
"EXAMPLES:\n"
"   ./uobjnew -l java -p 145         # summarize Java allocations in process 145\n"
"   ./uobjnew -l c -p 2020 1         # grab malloc() sizes and print every second\n"
"   ./uobjnew -l ruby -p 6712 -C 10  # top 10 Ruby types by number of allocations\n"
"   ./uobjnew -l ruby -p 6712 -S 10  # top 10 Ruby types by total size\n";

static const struct argp_option opts[] = {
	{ "language", 'l', "LANG", 0, "language to trace" },
	{ "pid", 'p', "PID", 0, "process id to attach to" },
	{ "interval", 0, "NUM", 0, "print every specified number of seconds" },
	{ "top-count", 'C', "NUM", 0, "number of most frequently allocated types to print" },
	{ "top-size", 'S', "NUM", 0, "number of largest types by allocated bytes to print" },
	{ "verbose", 'v', NULL, 0, "verbose mode: print the BPF program (for debugging purposes)" },
	{}
};

enum lang lang_id(const char *language)
{
	if (!strcmp(language, "c"))
		return LANG_C;
	else if (!strcmp(language, "java"))
		return LANG_JAVA;
	else if (!strcmp(language, "ruby"))
		return LANG_RUBY;
	else if (!strcmp(language, "tcl"))
		return LANG_TLC;
	else
		return LANG_NONE;
}

static const char *lang_str(enum lang language)
{
	switch (language) {
	case LANG_C: return "c";
	case LANG_JAVA: return "java";
	case LANG_RUBY: return "ruby";
	case LANG_TLC: return "tcl";
	default: return "unknow lang";
	}
	return NULL;
}

static const char *lang_so(enum lang language)
{
	switch (language) {
	case LANG_C: return "c";
	case LANG_JAVA: return "jvm";
	case LANG_RUBY: return "ruby";
	case LANG_TLC: return "tcl";
	default: return "unknow lang";
	}
	return NULL;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		if (arg)
			env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'C':
		if (arg)
			env.top_count = argp_parse_long(key, arg, state);
		break;
	case 'S':
		if (arg)
			env.top_size = argp_parse_long(key, arg, state);
		break;
	case 'l':
		if (!arg) {
			warning("Arg is NULL\n");
			argp_usage(state);
		}
		env.language = lang_id(arg);
		if (env.language == LANG_NONE)
			return ARGP_ERR_UNKNOWN;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0) {
			env.interval = argp_parse_long(key, arg, state);
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
{
	exiting = 1;
}

static void alloc_entries_print(struct alloc_entry *entries, enum lang language, int print_rows)
{
	unsigned int i = 0;

	printf("\n%-30s %8s %12s\n", "NAME/TYPE", "# ALLOCS", "# BYTES");
	for (; i < print_rows; i++) {
		switch (language) {
		case LANG_C:
		case LANG_JAVA:
			printf("block size %-19lld %8lld %12lld\n", entries[i].key.key.size,
				entries[i].val.num_allocs, entries[i].val.total_size);
			break;
		case LANG_RUBY:
		case LANG_TLC:
			printf("%-30s %8lld %12lld\n", entries[i].key.key.name,
				entries[i].val.num_allocs, entries[i].val.total_size);
			break;
		default:
			break;
		}
	}
}

int compare_entry(const void *a, const void *b)
{
	struct alloc_entry *v1 = (struct alloc_entry *)a;
	struct alloc_entry *v2 = (struct alloc_entry *)b;

	if (env.top_count)
		return v1->val.num_allocs - v2->val.num_allocs;
	else
		return v1->val.total_size - v2->val.total_size;
}

static int clear_data(int map_fd)
{
	int err = 0;
	struct key_t *lookup_key = NULL;
	struct key_t key = {};

	while (!bpf_map_get_next_key(map_fd, lookup_key, &key)) {
		err = bpf_map_delete_elem(map_fd, &key);
		if (err) {
			warning("delete_elem from uobjnew map err: %s\n", strerror(err));
			return err;
		}
	}

	return 0;
}

static int alloc_entries_sort_print(struct uobjnew_bpf *obj, enum lang language)
{
	struct key_t key = {};
	struct val_t val = {};
	struct key_t *lookup_key = NULL;
	struct alloc_entry arr[MAX_EVENTS_ENTRY] = {};
	int fd = bpf_map__fd(obj->maps.uobjnew_events_entry);
	int err, print_rows, rows = 0;

	while (!bpf_map_get_next_key(fd, lookup_key, &key)) {
		err = bpf_map_lookup_elem(fd, &key, &val);
		if (err) {
			warning("lookup_elem from uobjnew map err: %s\n", strerror(err));
			return err;
		}
		arr[rows].key = key;
		arr[rows++].val = val;
		lookup_key = &key;
	}

	err = clear_data(fd);
	if (err)
		return err;

	if (env.top_count)
		print_rows = min((int)env.top_count, (int)rows);
	else if (env.top_size)
		print_rows = min((int)env.top_size, (int)rows);
	else {
		print_rows = rows;
		goto entries_print;
	}

	qsort(arr, rows, sizeof(struct alloc_entry), compare_entry);

entries_print:
	alloc_entries_print(arr, language, print_rows);

	return err;
}

static int prog_attch(struct uobjnew_bpf *obj, pid_t pid)
{
	char binary_path[LIB_FILE_PATH_BUFF_SIZE] = {};
	unsigned int offset;
	struct bpf_link *link = NULL;
	int err = 0;

	err = resolve_binary_path(lang_so(env.language), pid,
				binary_path, sizeof(binary_path));
	if (err < 0) {
		warning("get binary file path failed\n");
		return -1;
	}

	switch (env.language) {
	case LANG_C:
		offset = get_elf_func_offset(binary_path, "malloc");
		link = bpf_program__attach_uprobe(obj->progs.handle_c_alloc,
						false,
						env.pid,
						binary_path,
						offset);
		obj->links.handle_c_alloc = link;
		break;
	case LANG_JAVA:
		link = bpf_program__attach_usdt(obj->progs.handle_java_alloc,
						pid,
						binary_path,
						"hotspot",
						"object__alloc",
						NULL);
		obj->links.handle_java_alloc = link;
		break;
	case LANG_RUBY:
		link = bpf_program__attach_usdt(obj->progs.handle_ruby_alloc,
						pid,
						binary_path,
						"ruby",
						"object__create",
						NULL);
		if (!link)
			goto __out;
		obj->links.handle_ruby_alloc = link;

		link = bpf_program__attach_usdt(obj->progs.handle_ruby_alloc_string,
						pid,
						binary_path,
						"ruby",
						"string__create",
						NULL);
		if (!link)
			goto __out;
		obj->links.handle_ruby_alloc_string = link;

		link = bpf_program__attach_usdt(obj->progs.handle_ruby_alloc_hash,
						pid,
						binary_path,
						"ruby",
						"hash__create",
						NULL);
		if (!link)
			goto __out;
		obj->links.handle_ruby_alloc_hash = link;

		link = bpf_program__attach_usdt(obj->progs.handle_ruby_alloc_array,
						pid,
						binary_path,
						"ruby",
						"array__create",
						NULL);
		if (!link)
			goto __out;
		obj->links.handle_ruby_alloc_array = link;
		break;
	case LANG_TLC:
		link = bpf_program__attach_usdt(obj->progs.handle_tcl_alloc,
						pid,
						binary_path,
						"tcl",
						"obj__create",
						NULL);
		obj->links.handle_tcl_alloc = link;
		break;
	default:
		return -1;
	}
__out:
	if (!link) {
		err = errno;
		warning("attach usdt/uprobe malloc failed: %s\n", strerror(err));
		return -1;
	}
	return 0;
}

static void alias_parse(char *prog)
{
	char *name = basename(prog);

	if (!strcmp(name, "cobjnew"))
		env.language = LANG_C;
	else if (!strcmp(name, "javaobjnew"))
		env.language = LANG_JAVA;
	else if (!strcmp(name, "rubyobjnew"))
		env.language = LANG_RUBY;
	else if (!strcmp(name, "tclobjnew"))
		env.language = LANG_TLC;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct uobjnew_bpf *obj = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	alias_parse(argv[0]);
	if (env.language == LANG_NONE)
		env.language = lang_id(detect_language(env.pid));

	if (env.language == LANG_NONE) {
		warning("Nothing to do.\n");
		return 1;
	}

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return 1;
	}

	obj = uobjnew_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	err = uobjnew_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = prog_attch(obj, env.pid);
	if (err < 0) {
		warning("attach usdt/uprobe failed\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing allocations in process %d (language: %s)... Ctrl-C to quit.\n",
		env.pid, lang_str(env.language));

	while (!exiting) {
		sleep(env.interval);
		err = alloc_entries_sort_print(obj, env.language);
		if (err)
			break;
	}

cleanup:
	uobjnew_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}