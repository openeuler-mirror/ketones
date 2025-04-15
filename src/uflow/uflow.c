// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Based on uflow.py - Sasha Goldshtein

#include "commons.h"
#include "compat.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"
#include "uflow.skel.h"
#include "uflow.h"

static volatile sig_atomic_t exiting;

static struct {
	pid_t pid;
	bool verbose;
	enum LANGUAGE language;
	const char *class;
	const char *method;
	bool filter_class;
	bool filter_method;
} env = {
	.pid = -1,
};

const char *argp_program_version = "uflow 0.1";
const char *argp_program_bug_address = "Youling Tang <tangyouling@kylinos.cn>";
const char argp_program_doc[] =
"Trace method execution flow in high-level languages.\n"
"\n"
"USAGE: uflow [-C CLASS] [-M METHOD] [-l {java,perl,php,python,ruby,tcl}]\n"
"             pid [-v]\n"
"\n"
"Examples:\n"
"    uflow -l java 185                # trace Java method calls in process 185\n"
"    uflow -l ruby 134                # trace Ruby method calls in process 134\n"
"    uflow -M indexOf -l java 185     # trace only 'indexOf'-prefixed methods\n"
"    uflow -C '<stdin>' -l python 180 # trace only REPL-defined methods\n";

const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "method", 'M', "METHOD", 0, "trace only calls to methods starting with this prefix", 0 },
	{ "class", 'C', "CLASS", 0, "trace only calls to classes starting with this prefix", 0 },
	{ "language", 'l', "LANGUAGE", 0, "language to trace [java,perl,php,python,ruby,tcl]", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "show the help", 0 },
	{}
};

const struct language_entry {
	const char *name;
	const char *entry_probe;
	const char *return_probe;
} languages[] = {
	[LA_NONE] = {
		.name = "none",
	},
	[LA_JAVA] = {
		.name = "java",
		.entry_probe = "method__entry",
		.return_probe = "method__return",
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
	case 'C':
		env.class = arg;
		env.filter_class = true;
		break;
	case 'M':
		env.method = arg;
		env.filter_method = true;
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

static void print_methods(const struct call_t *calls)
{
	__u64 depth = calls->depth & (~(1ULL << 63));

	while (--depth)
		printf("  ");

	if (calls->depth & (1ULL << 63))
		printf("<-");
	else
		printf("->");

	printf("%s.%s\n", calls->clazz, calls->method);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct call_t *calls = data;

	printf("%-3d %-7lld %-7lld %-8.3f ", calls->cpu, calls->pid >> 32, calls->pid & 0xFFFFFFFF,
		time_since_start());

	print_methods(calls);

	return 0;
}

static int attach_language_usdt(struct uflow_bpf *obj)
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

	if (!strcmp(name, "javaflow"))
		env.language = LA_JAVA;
	else if (!strcmp(name, "perlflow"))
		env.language = LA_PERL;
	else if (!strcmp(name, "phpflow"))
		env.language = LA_PHP;
	else if (!strcmp(name, "pythonflow"))
		env.language = LA_PYTHON;
	else if (!strcmp(name, "rubyflow"))
		env.language = LA_RUBY;
	else if (!strcmp(name, "tclflow"))
		env.language = LA_TCL;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct uflow_bpf *obj;
	struct bpf_buffer *buf = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	alias_parse(argv[0]);

	if (env.language == LA_NONE)
		str2language(detect_language(env.pid), &env.language);

	if (!bpf_is_root())
		return 0;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return 1;
	}

	obj = uflow_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	obj->rodata->target_pid = env.pid;
	obj->rodata->target_language = env.language;

	if (env.filter_class) {
		obj->rodata->target_class_sz = strlen(env.class);
		obj->rodata->filter_class = env.filter_class;
		strcpy(obj->bss->target_class, env.class);
	}
	if (env.filter_method) {
		obj->rodata->target_method_sz = strlen(env.method);
		obj->rodata->filter_method = env.filter_method;
		strcpy(obj->bss->target_method, env.method);
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		warning("Failed to create ring/perf buffer\n");
		goto cleanup;
	}

	err = uflow_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		goto cleanup;
	}

	err = attach_language_usdt(obj);
	if (err) {
		warning("Failed to attch BPF USDT programs\n");
		goto cleanup;
	}

	err = uflow_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF tracepoints programs\n");
		goto cleanup;
	}

	printf("Tracing method calls in %s process %d... Ctrl-C to quit.\n",
	       languages[env.language].name, env.pid);

	printf("%-3s %-7s %-7s %-8s %s\n", "CPU", "PID", "TID", "TIME(s)", "METHOD");

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Failed to set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* Loop */
	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling buffer: %s\n", strerror(-err));
			goto cleanup;
		}

		/* retset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	uflow_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
