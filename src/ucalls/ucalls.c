// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Based on ucalls.py - Sasha Goldshtein

#include "commons.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"
#include "syscall_helpers.h"
#include "ucalls.skel.h"
#include "ucalls.h"
#include <libgen.h>

static volatile sig_atomic_t exiting;

static struct {
	bool verbose;
	enum LANGUAGE language;
	int top;
	bool do_latency;
	bool do_syscalls;
	bool in_milliseconds;
	pid_t pid;
	int interval;
} env = {
	.pid = -1,
	.interval = 99999999,
};

const char *argp_program_version = "ucalls 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize method calls in high-level languages and/or system calls.\n"
"\n"
"USAGE: ucalls [-l {java,perl,php,python,ruby,tcl}] [-h] [-T TOP] [-L] [-S]\n"
"              [-v] [-m] pid [interval]\n"
"\n"
"Examples:\n"
"    ./ucalls -l java 185        # trace Java calls and print statistics on ^C\n"
"    ./ucalls -l python 2020 1   # trace Python calls and print every second\n"
"    ./ucalls -l java 185 -S     # trace Java calls and syscalls\n"
"    ./ucalls 6712 -S            # trace only syscall counts\n"
"    ./ucalls -l ruby 1344 -T 10 # trace top 10 Ruby method calls\n"
"    ./ucalls -l ruby 1344 -L    # trace Ruby calls including latency\n"
"    ./ucalls -l php 443 -LS     # trace PHP calls and syscalls with latency\n"
"    ./ucalls -l python 2020 -mL # trace Python calls including latency in ms\n";

const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "language", 'l', "LANGUAGE", 0, "language to trace [java,perl,php,python,ruby,tcl] (if none, trace syscalls only)" },
	{ "top", 'T', "TOP", 0, "number of most frequent/slow calls to print" },
	{ "latency", 'L', NULL, 0, "record method latency from enter to exit (except recursive calls)" },
	{ "syscalls", 'S', NULL, 0, "record syscall latency (adds overhead)" },
	{ "milliseconds", 'm', NULL, 0, "report times in milliseconds (default is microseconds)" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "show the help" },
	{}
};

const struct language_entry {
	const char *name;
	const char *entry_probe;
	const char *return_probe;
	const char *extra_message;
} languages[] = {
	[LA_NONE] = {
		.name = "none",
	},
	[LA_JAVA] = {
		.name = "java",
		.entry_probe = "method__entry",
		.return_probe = "method__return",
		.extra_message = "If you do not see any results, make sure you ran java "
				 "with option -XX:+ExtendedDTraceProbes",
	},
	[LA_PERL] = {
		.name = "perl",
		.entry_probe = "sub__entry",
		.return_probe = "sub__return",
	},
	[LA_PHP] = {
		.name = "php",
		.entry_probe = "function__entry",
		.return_probe = "function__return",
		.extra_message = "If you do not see any results, make sure the environment "
				 "variable USE_ZEND_DTRACE is set to 1",
	},
	[LA_PYTHON] = {
		.name = "python",
		.entry_probe = "function__entry",
		.return_probe = "function__return",
	},
	[LA_RUBY] = {
		.name = "ruby",
		.entry_probe = "method__entry",
		.return_probe = "method__return",
	},
	[LA_TCL] = {
		.name = "tcl",
		.entry_probe = "proc__entry",
		.return_probe = "proc__return",
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

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'T':
		env.top = argp_parse_long(key, arg, state);
		break;
	case 'S':
		env.do_syscalls = true;
		break;
	case 'L':
		env.do_latency = true;
		break;
	case 'm':
		env.in_milliseconds = true;
		break;
	case 'l':
		if (!str2language(arg, &env.language)) {
			warning("Unknown language: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0)
			env.pid = argp_parse_pid(key, arg, state);
		else if (state->arg_num == 1)
			env.interval = argp_parse_long(key, arg, state);
		else {
			warning("Unrecognized positional arguments: %s", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (env.pid == -1) {
			warning("not process id to attach\n");
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

static int clear_data(struct ucalls_bpf *obj)
{
	int err = 0, fd;
	struct method_t prev = {}, next;

	if (env.do_latency)
		fd = bpf_map__fd(obj->maps.times);
	else
		fd = bpf_map__fd(obj->maps.counts);

	while (!bpf_map_get_next_key(fd, &prev, &next)) {
		err = bpf_map_delete_elem(fd, &next);
		if (err)
			goto cleanup;
	}

	if (!env.do_syscalls)
		return 0;

	__u64 sys_prev = -1, sys_next;
	if (env.do_latency)
		fd = bpf_map__fd(obj->maps.systimes);
	else
		fd = bpf_map__fd(obj->maps.syscounts);

	while (!bpf_map_get_next_key(fd, &sys_prev, &sys_next)) {
		err = bpf_map_delete_elem(fd, &sys_next);
		if (err)
			goto cleanup;
	}

cleanup:
	if (err)
		warning("bpf_map_delete_elem failed: %d\n", err);

	return err;
}

struct val {
	struct method_t method;
	struct info_t info;
};

static int sort_column(const void *a, const void *b)
{
	const struct val *v1 = a;
	const struct val *v2 = b;

	if (env.do_latency)
		return v1->info.total_ns - v2->info.total_ns;
	else
		return v1->info.num_calls - v2->info.num_calls;
}

static int print_data(struct ucalls_bpf *obj)
{
	int err = 0, rows = 0, fd;
	struct val values[MAX_ENTRIES] = {};

	printf("\n%-50s %8s", "METHOD", "# CALLS");
	if (env.do_latency)
		 printf(" %8s", env.in_milliseconds ? "TIME (ms)" : "TIME (us)");
	printf("\n");

	struct method_t prev = {};
	if (env.do_latency) {
		fd = bpf_map__fd(obj->maps.times);

		while (!bpf_map_get_next_key(fd, &prev, &values[rows].method)) {
			err = bpf_map_lookup_elem(fd, &values[rows].method, &values[rows].info);
			if (err) {
				warning("bpf_map_lookup_elem failed: %d\n", err);
				break;
			}
			prev = values[rows++].method;
			if (rows >= MAX_ENTRIES)
				break;
		}
	} else {
		fd = bpf_map__fd(obj->maps.counts);

		while (!bpf_map_get_next_key(fd, &prev, &values[rows].method)) {
			err = bpf_map_lookup_elem(fd, &values[rows].method, &values[rows].info.num_calls);
			if (err) {
				warning("bpf_map_lookup_elem failed: %d\n", err);
				break;
			}
			prev = values[rows++].method;
			if (rows >= MAX_ENTRIES)
				break;
		}
	}

	if (!env.do_syscalls)
		goto skip_syscalls;

	__u64 prev_key = -1, next_key;
	if (env.do_latency) {
		fd = bpf_map__fd(obj->maps.systimes);

		while (!bpf_map_get_next_key(fd, &prev_key, &next_key)) {
			err = bpf_map_lookup_elem(fd, &next_key, &values[rows].info);
			if (err) {
				warning("bpf_map_lookup_elem failed: %d\n", err);
				break;
			}
			prev_key = next_key;
			syscall_name(next_key, values[rows++].method.clazz,
				     sizeof(values[rows++].method.clazz));
		}
	} else {
		fd = bpf_map__fd(obj->maps.syscounts);

		while (!bpf_map_get_next_key(fd, &prev_key, &next_key)) {
			err = bpf_map_lookup_elem(fd, &next_key, &values[rows].info.num_calls);
			if (err) {
				warning("bpf_map_lookup_elem failed: %d\n", err);
				break;
			}
			prev_key = next_key;
			syscall_name(next_key, values[rows++].method.clazz,
				     sizeof(values[rows++].method.clazz));
		}
	}

skip_syscalls:
	qsort(values, rows, sizeof(values[0]), sort_column);
	int top = 0;

	if (env.top) {
		if (env.top <= rows)
			top = rows - env.top;
		else
			top = env.top;
	}

	for (int i = top; i < rows; i++) {
		if (values[i].method.method[0]) {
			char buf[MAX_STRING_LEN*2];

			sprintf(buf, "%s.%s", values[i].method.clazz, values[i].method.method);
			printf("%-50s ", buf);
		} else {
			printf("%-50s ", values[i].method.clazz);
		}

		printf("%8lld", values[i].info.num_calls);
		if (env.do_latency)
			printf(" %8.2f", env.in_milliseconds ?
			       values[i].info.total_ns / 1e6 :
			       values[i].info.total_ns / 1e3);
		printf("\n");
	}

	return err;
}

static int attach_language_usdt(struct ucalls_bpf *obj)
{
	int err = 0;
	char binary_path[PATH_MAX];

	if (env.language == LA_NONE)
		return 0;

	if (resolve_binary_path("", env.pid, binary_path, sizeof(binary_path)))
		return 1;

	obj->links.trace_entry = bpf_program__attach_usdt(obj->progs.trace_entry,
							  env.pid, binary_path,
							  languages[env.language].name,
							  languages[env.language].entry_probe,
							  NULL);
	if (!obj->links.trace_entry) {
		err = errno;
		warning("attach usdt %s failed: %s\n", languages[env.language].entry_probe,
			strerror(errno));
		return err;
	}

	if (!env.do_latency)
		return 0;

	obj->links.trace_return = bpf_program__attach_usdt(obj->progs.trace_return,
							   env.pid, binary_path,
							   languages[env.language].name,
							   languages[env.language].return_probe,
							   NULL);
	if (!obj->links.trace_return) {
		err = errno;
		warning("attach usdt %s failed: %s\n", languages[env.language].return_probe,
			strerror(errno));
		return err;
	}

	return 0;
}

static void alias_parse(char *prog)
{
	char *name = basename(prog);

	if (!strcmp(name, "javacalls"))
		env.language = LA_JAVA;
	else if (!strcmp(name, "perlcalls"))
		env.language = LA_PERL;
	else if (!strcmp(name, "phpcalls"))
		env.language = LA_PHP;
	else if (!strcmp(name, "pythoncalls"))
		env.language = LA_PYTHON;
	else if (!strcmp(name, "rubycalls"))
		env.language = LA_RUBY;
	else if (!strcmp(name, "tclcalls"))
		env.language = LA_TCL;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct ucalls_bpf *obj;
	int err;

	init_syscall_names();

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	alias_parse(argv[0]);

	if (env.language == LA_NONE)
		str2language(detect_language(env.pid), &env.language);

	if (env.language == LA_NONE && !env.do_syscalls) {
		warning("Nothing to do; use -S to trace syscalls.\n");
		return 1;
	}

	if (!bpf_is_root())
		return 0;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return 1;
	}

	obj = ucalls_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	obj->rodata->target_pid = env.pid;
	obj->rodata->target_language = env.language;
	obj->rodata->do_latency = env.do_latency;
	obj->rodata->do_syscalls = env.do_syscalls;

	if (!env.do_syscalls) {
		bpf_program__set_autoload(obj->progs.tracepoint_syscall_enter, false);
		bpf_program__set_autoload(obj->progs.tracepoint_syscall_exit, false);
	} else if (!env.do_latency) {
		bpf_program__set_autoload(obj->progs.tracepoint_syscall_exit, false);
	}

	err = ucalls_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		goto cleanup;
	}

	err = attach_language_usdt(obj);
	if (err) {
		warning("Failed to attch BPF USDT programs\n");
		goto cleanup;
	}

	err = ucalls_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF tracepoints programs\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Failed to set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.do_syscalls)
		printf("Attached kernel tracepoints for syscall tracing.\n");

	printf("Tracing calls in process %d (language: %s)... Ctrl-C to quit.\n",
	       env.pid, languages[env.language].name);

	if (languages[env.language].extra_message)
		printf("%s\n", languages[env.language].extra_message);

	while (!exiting) {
		sleep(env.interval);

		err = print_data(obj);
		if (err)
			break;
		err = clear_data(obj);
		if (err)
			break;
	}

cleanup:
	free_syscall_names();
	ucalls_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
