// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on ustat.py - Sasha Goldshtein

#include "commons.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"
#include "ustat.skel.h"
#include "ustat.h"
#include <libgen.h>
#include <dirent.h>

static volatile sig_atomic_t exiting;

static struct {
	bool verbose;
	enum LANGUAGE language;
	int interval;
	int count;
	int maxrows;
	bool noclear;
	enum CATEGORY sort;
} env = {
	.language = LA_NONE,
	.interval = 1,
	.count = 99999999,
	.maxrows = 20,
	.noclear = false,
};

const char *argp_program_version = "ustat 0.1";
const char *argp_program_bug_address = "Yun Lu <luyun@kylinos.cn>";
const char argp_program_doc[] =
"Activity stats from high-level languages, including exceptions\n"
"method calls, class loads, garbage collections, and more.\n"
"For Linux, uses BCC, eBPF.\n"
"\n"
"USAGE: ustat [-l {java,node,perl,php,python,ruby,tcl}] [-C]\n"
"	      [-S {cload,excp,gc,method,objnew,thread}] [-r MAXROWS] [-d]\n"
"	      [interval [count]]\n"
"\n"
"Examples:\n"
"	./ustat              # stats for all languages, 1 second refres\n"
"	./ustat -C           # don't clear the screen\n"
"	./ustat -l java      # Java processes only\n"
"	./ustat 5            # 5 second summaries\n"
"	./ustat 5 10         # 5 second summaries, 10 times only\n";

const struct argp_option opts[] = {
	{ "verbose", 'd', NULL, 0, "Verbose debug output" },
	{ "language", 'l', "LANGUAGE", 0, "language to trace [java,node,perl,php,python,ruby,tcl] (default: all languages)" },
	{ "noclear", 'C', NULL, 0, "don't clear the screen" },
	{ "sort", 'S', "SORT", 0, "sort by this field (cload,excp,gc,method,objnew,thread),descending order" },
	{ "maxrows", 'r', "MAXROWS", 0, "maximum rows to print, default 20" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "show the help" },
	{}
};

struct val {
	__u32 pid;
	char comm[128];
	enum LANGUAGE lang;
	__u64 method_counts;
	__u64 gc_counts;
	__u64 objnew_counts;
	__u64 cload_counts;
	__u64 excp_counts;
	__u64 thread_counts;
};

const struct language_entry {
	const char *name;
	const char *procnames[2];
	int proc_cnt;
} languages[] = {
	[LA_NONE] = {
		.name = "none",
	},
	[LA_JAVA] = {
		.name = "hotspot",
		.procnames[0] = "java",
		.proc_cnt = 1,
	},
	[LA_NODE] = {
		.name = "node",
		.procnames[0] = "node",
		.proc_cnt = 1,
	},
	[LA_PERL] = {
		.name = "perl",
		.procnames[0] = "perl",
		.proc_cnt = 1,
	},
	[LA_PHP] = {
		.name = "php",
		.procnames[0] = "php",
		.proc_cnt = 1,
	},
	[LA_PYTHON] = {
		.name = "python",
		.procnames[0] = "python",
		.proc_cnt = 1,
	},
	[LA_RUBY] = {
		.name = "ruby",
		.procnames[0] = "ruby",
		.procnames[1] = "irb",
		.proc_cnt = 2,
	},
	[LA_TCL] = {
		.name = "tcl",
		.procnames[0] = "tclsh",
		.procnames[1] = "wish",
		.proc_cnt = 2,
	},
};

static bool str2language(const char *la_str, enum LANGUAGE *language)
{
	if (!la_str) {
		 *language = LA_NONE;
		 return true;
	}

	if (!strcmp(la_str, "java"))
		*language = LA_JAVA;
	else if (!strcmp(la_str, "node"))
		*language = LA_NODE;
	else if (!strcmp(la_str, "perl"))
		*language = LA_PERL;
	else if (!strcmp(la_str, "php"))
		*language = LA_PHP;
	else if (!strcmp(la_str, "python"))
		*language = LA_PYTHON;
	else if (!strcmp(la_str, "ruby"))
		*language = LA_RUBY;
	else if (!strcmp(la_str, "tcl"))
		*language = LA_TCL;
	else
		return false;

	return true;
}

static bool str2category(const char *ca_str, enum CATEGORY *category)
{
	if (!ca_str) {
		*category = CA_NONE;
		return false;
	}

	if (!strcmp(ca_str, "cload"))
		*category = CA_CLOAD;
	else if (!strcmp(ca_str, "excp"))
		*category = CA_EXCP;
	else if (!strcmp(ca_str, "gc"))
		*category = CA_GC;
	else if (!strcmp(ca_str, "method"))
		*category = CA_METHOD;
	else if (!strcmp(ca_str, "objnew"))
		*category = CA_OBJNEW;
	else if (!strcmp(ca_str, "thread"))
		*category = CA_THREAD;
	else
		return false;

	return true;
}

static const char *lang_so(enum LANGUAGE language)
{
	switch (language) {
	case LA_JAVA: return "jvm";
	case LA_NODE: return "";
	case LA_PERL: return "perl";
	case LA_PHP: return "php";
	case LA_PYTHON: return "";
	case LA_RUBY: return "ruby";
	case LA_TCL: return "tcl";
	default: return "unknow lang";
	}
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'd':
		env.verbose = true;
		break;
	case 'l':
		if (!str2language(arg, &env.language)) {
			warning("Unknown language: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'C':
		env.noclear = true;
		break;
	case 'S':
		if (!str2category(arg, &env.sort)) {
			warning("Unknown sort field: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		env.maxrows = argp_parse_long(key, arg, state);
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0)
			env.interval = argp_parse_pid(key, arg, state);
		else if (state->arg_num == 1)
			env.count = argp_parse_pid(key, arg, state);
		else {
			warning("Unrecognized positional arguments: %s", arg);
			argp_usage(state);
		}
		break;
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

static void alias_parse(char *prog)
{
	char *name = basename(prog);

	if (!strcmp(name, "javastat"))
		env.language = LA_JAVA;
	else if (!strcmp(name, "nodestat"))
		env.language = LA_NODE;
	else if (!strcmp(name, "perlstat"))
		env.language = LA_PERL;
	else if (!strcmp(name, "phpstat"))
		env.language = LA_PHP;
	else if (!strcmp(name, "pythonstat"))
		env.language = LA_PYTHON;
	else if (!strcmp(name, "rubystat"))
		env.language = LA_RUBY;
	else if (!strcmp(name, "tclstat"))
		 env.language = LA_TCL;
}

int is_digit(const char *str) {
	int len = strlen(str);

	for (int i = 0; i < len; i++) {
		if (!isdigit((unsigned char)str[i])) {
			return 0;
		}
	}

	return 1;
}

#define DEF_BPF_ATTACH(trace_func, trace_entry)			\
if (!strcmp(trace_entry, "ExceptionOccurred__entry"))		\
	strcpy(name, "hotspot_jni");				\
else								\
	strcpy(name, languages[lang].name);			\
								\
link = bpf_program__attach_usdt(obj->progs.trace_func,		\
		pid, binary_path, name,				\
		trace_entry, NULL);				\
if (!link) {							\
	printf("attach %s failed\n", trace_entry);		\
	goto out;						\
}								\
obj->links.trace_func = link

static int attach_language_usdt(struct ustat_bpf *obj, __u32 pid, enum LANGUAGE lang)
{
	char name[32];
	char binary_path[PATH_MAX];
	struct bpf_link *link = NULL;

	if (resolve_binary_path(lang_so(lang), pid, binary_path, sizeof(binary_path))) {
		warning("get binary file path failed\n");
		return -1;
	}

	switch (lang) {
	case LA_JAVA:
		DEF_BPF_ATTACH(trace_java_gc__begin, "gc__begin");
		DEF_BPF_ATTACH(trace_java_mem__pool__gc__begin, "mem__pool__gc__begin");
		DEF_BPF_ATTACH(trace_java_thread__start, "thread__start");
		DEF_BPF_ATTACH(trace_java_class__loaded, "class__loaded");
		DEF_BPF_ATTACH(trace_java_object__alloc, "object__alloc");
		DEF_BPF_ATTACH(trace_java_method__entry, "method__entry");
		DEF_BPF_ATTACH(trace_java_ExceptionOccurred__entry, "ExceptionOccurred__entry");
		break;
	case LA_NODE:
		DEF_BPF_ATTACH(trace_node_gc_start, "gc__start");
		break;
	case LA_PERL:
		DEF_BPF_ATTACH(trace_perl_sub__entry, "sub__entry");
		break;
	case LA_PHP:
		DEF_BPF_ATTACH(trace_php_function__entry, "function__entry");
		DEF_BPF_ATTACH(trace_php_compile__file__entry, "compile__file__entry");
		DEF_BPF_ATTACH(trace_php_exception__thrown, "exception__thrown");
		break;
	case LA_PYTHON:
		DEF_BPF_ATTACH(trace_python_function__entry, "function__entry");
		DEF_BPF_ATTACH(trace_python_gc__start, "gc__start");
		break;
	case LA_RUBY:
		DEF_BPF_ATTACH(trace_ruby_method__entry, "method__entry");
		DEF_BPF_ATTACH(trace_ruby_cmethod__entry, "cmethod__entry");
		DEF_BPF_ATTACH(trace_ruby_gc__mark__begin, "gc__mark__begin");
		DEF_BPF_ATTACH(trace_ruby_gc__sweep__begin, "gc__sweep__begin");
		DEF_BPF_ATTACH(trace_ruby_object__create, "object__create");
		DEF_BPF_ATTACH(trace_ruby_hash__create, "hash__create");
		DEF_BPF_ATTACH(trace_ruby_string__create, "string__create");
		DEF_BPF_ATTACH(trace_ruby_array__create, "array__create");
		DEF_BPF_ATTACH(trace_ruby_require__entry, "require__entry");
		DEF_BPF_ATTACH(trace_ruby_load__entry, "load__entry");
		DEF_BPF_ATTACH(trace_ruby_raise, "raise");
		break;
	case LA_TCL:
		DEF_BPF_ATTACH(trace_tcl_proc__entry, "proc__entry");
		DEF_BPF_ATTACH(trace_tcl_obj__create, "obj__create");
		break;
	default:
		return -1;
	}

out:
	if (!link) {
		warning("pid:%d attach usdt failed: %s\n", pid, strerror(errno));
		return 0;
	}
	return 0;
}

static int get_pid_comm(struct val *targets, int index, int pid)
{
	char cmdline_filepath[64];
	FILE* cmdline_file;
	size_t len = 0;

	snprintf(cmdline_filepath, sizeof(cmdline_filepath),
		 "/proc/%d/cmdline", pid);
	cmdline_file = fopen(cmdline_filepath, "r");
	if (cmdline_file)
	{
		len = fread(targets[index].comm, sizeof(char), sizeof(targets[index].comm),
			    cmdline_file);
		if (len > 0) {
			for (int i = 0; i < len-1; i++) {
				if (targets[index].comm[i] == '\0')
					targets[index].comm[i] = ' ';
			}
		}
		fclose(cmdline_file);
	}

	return len;
}

static int find_target_pid(struct val *targets, const char* procnames[], int procname_count){
	int cnt = 0;
	DIR *dir;
	struct dirent *entry;

	dir = opendir("/proc");

	while ((entry = readdir(dir)) != NULL) {
		if (is_digit(entry->d_name)) {
			char comm_filepath[64];
			int pid = atoi(entry->d_name);
			FILE* comm_file;
			char comm[32];

			snprintf(comm_filepath, sizeof(comm_filepath), "/proc/%d/comm", pid);
			comm_file = fopen(comm_filepath, "r");
			if (comm_file == NULL) {
				continue;
			}

			if (fgets(comm, sizeof(comm), comm_file) != NULL) {
				int match_found = 0;

				comm[strcspn(comm, "\n")] = '\0';
				for (int j = 0; j < procname_count; j++) {
					if (strcmp(comm, procnames[j]) == 0) {
						match_found = 1;
						break;
					}
				}

				fclose(comm_file);
				if (match_found && get_pid_comm(targets, cnt, pid) > 0) {
					targets[cnt].pid = pid;
					if (strcmp(comm, "ruby") == 0 || strcmp(comm, "irb") == 0)
						targets[cnt].lang = LA_RUBY;
					else if (strcmp(comm, "tclsh") == 0 || strcmp(comm, "wish") == 0)
						targets[cnt].lang = LA_TCL;
					else
						str2language(comm, &targets[cnt].lang);

					cnt++;
				}
			}

		}
	}

	return cnt;
}

static void get_counts(struct ustat_bpf *obj, struct val *targets, int cnt)
{
	int fd;
	enum LANGUAGE lang;
	__u32 pid;

	for (int i = 0; i < cnt; i++) {
		lang = targets[i].lang;
		pid = targets[i].pid;
		switch (lang) {
		case LA_JAVA:
			fd = bpf_map__fd(obj->maps.java_gc_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].gc_counts);
			fd = bpf_map__fd(obj->maps.java_thread_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].thread_counts);
			fd = bpf_map__fd(obj->maps.java_cload_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].cload_counts);
			fd = bpf_map__fd(obj->maps.java_objnew_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].objnew_counts);
			fd = bpf_map__fd(obj->maps.java_method_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].method_counts);
			fd = bpf_map__fd(obj->maps.java_excp_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].excp_counts);
			fd = bpf_map__fd(obj->maps.java_gc_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].gc_counts);
			break;
		case LA_NODE:
			fd = bpf_map__fd(obj->maps.node_gc_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].gc_counts);
			break;
		case LA_PERL:
			fd = bpf_map__fd(obj->maps.perl_method_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].method_counts);
			break;
		case LA_PHP:
			fd = bpf_map__fd(obj->maps.php_method_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].method_counts);
			fd = bpf_map__fd(obj->maps.php_cload_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].cload_counts);
			fd = bpf_map__fd(obj->maps.php_excp_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].excp_counts);
			break;
		case LA_PYTHON:
			fd = bpf_map__fd(obj->maps.python_method_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].method_counts);
			fd = bpf_map__fd(obj->maps.python_gc_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].gc_counts);
			break;
		case LA_RUBY:
			fd = bpf_map__fd(obj->maps.ruby_method_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].method_counts);
			fd = bpf_map__fd(obj->maps.ruby_gc_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].gc_counts);
			fd = bpf_map__fd(obj->maps.ruby_objnew_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].objnew_counts);
			fd = bpf_map__fd(obj->maps.ruby_cload_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].cload_counts);
			fd = bpf_map__fd(obj->maps.ruby_excp_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].excp_counts);
			break;
		case LA_TCL:
			fd = bpf_map__fd(obj->maps.tcl_method_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].method_counts);
			fd = bpf_map__fd(obj->maps.tcl_objnew_counts);
			bpf_map_lookup_and_delete_elem(fd, &pid, &targets[i].objnew_counts);
			break;
		default:
			break;
		}
	}
}

static int sort_column(const void *obj1, const void *obj2)
{
	struct val *t1 = (struct val *)obj1;
	struct val *t2 = (struct val *)obj2;

	switch (env.sort) {
	case CA_THREAD:
		return (t2->thread_counts - t1->thread_counts);
	case CA_METHOD:
		return (t2->method_counts - t1->method_counts);
	case CA_OBJNEW:
		return (t2->objnew_counts - t1->objnew_counts);
	case CA_CLOAD:
		return (t2->cload_counts - t1->cload_counts);
	case CA_EXCP:
		return (t2->excp_counts - t1->excp_counts);
	case CA_GC:
	default:
		return (t2->gc_counts -t1->gc_counts);
	}
}

static void print_data(struct val *targets, int cnt) {
	FILE* load_file;
        char load[64];
	char time_now[16];

	strftime_now(time_now, sizeof(time_now), "%H:%M:%S");
	load_file = fopen("/proc/loadavg", "r");
	if (load_file == NULL)
		return;

	if (fgets(load, sizeof(load), load_file) != NULL)
		printf("%-8s loadavg: %s\n", time_now, load);
	fclose(load_file);

	printf("%-8s %-20s %-10s %-6s %-10s %-8s %-6s %-6s\n",
		"PID", "CMDLINE", "METHOD/s", "GC/s", "OBJNEW/s", "CLOAD/s", "EXC/s", "THR/s");

	for (int i = 0; i < cnt; i++) {
		printf("%-8d %-20.20s %-10lld %-6lld %-10lld %-8lld %-6lld %-6lld \n",
			targets[i].pid, targets[i].comm, targets[i].method_counts/env.interval,
			targets[i].gc_counts/env.interval, targets[i].objnew_counts/env.interval,
			targets[i].cload_counts/env.interval, targets[i].excp_counts/env.interval,
			targets[i].thread_counts/env.interval);
	}
	return;
}

static int run_loop(struct ustat_bpf *obj)
{
	int pid_cnt = 0, err;
	struct val targets[MAX_ENTRIES] = {};

	if (env.language == LA_NONE) {
		const char *procnames[] = {"java", "node", "perl", "php", "python",
					   "ruby", "irb", "tclsh", "wish"};
		pid_cnt = find_target_pid(targets, procnames,
					  sizeof(procnames)/sizeof(procnames[0]));
	} else {
		pid_cnt = find_target_pid(targets, (const char **)languages[env.language].procnames,
					  languages[env.language].proc_cnt);
	}
	if (!pid_cnt) {
		printf("can't find target pid!\n");
		return 1;
	}

	for (int i = 0; i < pid_cnt; i++) {
		err = attach_language_usdt(obj, targets[i].pid, targets[i].lang);
		if (err)
			return 1;
	}

	err = ustat_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF tracepoints programs\n");
		return 1;
	}

	sleep(env.interval);

	get_counts(obj, targets, pid_cnt);

	if (env.sort)
		 qsort(targets, pid_cnt, sizeof(struct val), sort_column);

	if (!env.noclear) {
		err = system("clear");
		if (err)
			return 1;
	}

	print_data(targets, pid_cnt);

	ustat_bpf__detach(obj);

	return 0;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct ustat_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	alias_parse(argv[0]);

	if (!bpf_is_root())
		return 0;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return 1;
	}

	obj = ustat_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	err = ustat_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing... Output every %d secs. Hit Ctrl-C to end\n", env.interval);

	while (!exiting && env.count) {
		if (run_loop(obj))
			break;
		env.count--;
	}
	printf("Detaching...\n");

cleanup:
	ustat_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}

