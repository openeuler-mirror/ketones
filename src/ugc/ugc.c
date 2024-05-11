// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on ugc.py - Sasha Goldshtein

#include "commons.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"
#include "trace_helpers.h"
#include "compat.h"
#include "ugc.h"
#include "ugc.skel.h"
#include <libgen.h>

static volatile sig_atomic_t exiting;

static struct {
	bool verbose;
	enum LANGUAGE language;
	bool milliseconds;
	int minimum;
	pid_t pid;
	char *filter;
} env = {
	.pid = -1,
	.minimum = 0,
};

const char *argp_program_version = "ugc 0.1";
const char *argp_program_bug_address = "Yun Lu <luyun@kylinos.cn>";
const char argp_program_doc[] =
"Summarize garbage collection events in high-level languages.\n"
"\n"
"USAGE: ugc [-v] [-m] [-M MSEC] [-F FILTER] {node,python,ruby} pid\n"
"\n"
"Examples:\n"
"    ./ugc -l node 185        # trace Node GCs in process 185\n"
"    ./ugc -l ruby 1344 -m    # trace Ruby GCs reporting in ms\n"
"    ./ugc -M 10 -l node 185  # trace only Node GCs longer than 10ms\n";

const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "language", 'l', "LANGUAGE", 0, "language to trace [node,python,ruby]", 0 },
	{ "milliseconds", 'm', NULL, 0, "report times in milliseconds (default is microseconds)", 0 },
	{ "minimum", 'M', "MIN-MS", 0, "display only GCs longer than this many milliseconds", 0 },
	{ "filter", 'F', "FILTER", 0, "display only GCs whose description contains this text", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "show the help", 0 },
	{}
};

const struct language_entry {
	const char *name;
	const char *begin_probe[2];
	const char *end_probe[2];
} languages[] = {
	[LA_NONE] = {
		.name = "none",
	},
	[LA_NODE] = {
		.name = "node",
		.begin_probe[0] = "gc__start",
		.end_probe[0] = "gc__done",
	},
	[LA_PYTHON] = {
		.name = "python",
		.begin_probe[0] = "gc__start",
		.end_probe[0] = "gc__done",
	},
	[LA_RUBY] = {
		.name = "ruby",
		.begin_probe[0] = "gc__mark__begin",
		.end_probe[0] = "gc__mark__end",
		.begin_probe[1] = "gc__sweep__begin",
		.end_probe[1] = "gc__sweep__end",
	},
};

static const char *lang_str(enum LANGUAGE language)
{
	switch (language) {
		case LA_RUBY: return "ruby";
		case LA_NODE: return "node";
		case LA_PYTHON: return "python";
		default: return "unknow lang";
	}
}

static const char *lang_so(enum LANGUAGE language)
{
	switch (language) {
		case LA_RUBY: return "ruby";
		case LA_NODE: return "node";
		case LA_PYTHON: return "";
		default: return "unknow lang";
	}
}

static bool str2language(const char *la_str, enum LANGUAGE *language)
{
	if (!la_str) {
		*language = LA_NONE;
		return true;
	}

	if (!strcmp(la_str, "node"))
		*language = LA_NODE;
	else if (!strcmp(la_str, "python"))
		*language = LA_PYTHON;
	else if (!strcmp(la_str, "ruby"))
		*language = LA_RUBY;
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
	case 'm':
		env.milliseconds = true;
		break;
	case 'l':
		if (!str2language(arg, &env.language)) {
			warning("Unknown language: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'M':
		env.minimum = argp_parse_long(key, arg, state);
		break;
	case 'F':
		env.filter = arg;
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct gc_event_t *e = data;
	char description[256];

	if (env.language == LA_NODE) {
		switch (e->field1) {
		case 1:
			sprintf(description, "GC scavenge");
			break;
		case 2:
			sprintf(description, "GC mark-sweep-compact");
			break;
		case 4:
			sprintf(description, "GC incremental mark");
			break;
		case 8:
			sprintf(description, "GC weak callbacks");
			break;
		default:
			sprintf(description, "No matched GC type");
			break;
		}
	}

	else if (env.language == LA_PYTHON) {
		sprintf(description, "gen %ld GC collected %ld objects", e->field1, e->field2);
	}

	else if (env.language == LA_RUBY) {
		if (e->probe_index == 1)
			sprintf(description, "GC mark stage");
		else
			sprintf(description, "GC sweep stage");
	}

	if (env.filter && strstr(description, env.filter) == NULL)
		return 0;

	printf("%-8.3f %-8.2f %s\n", time_since_start(),
			env.milliseconds ? e->elapsed_ns / 1e6 : e->elapsed_ns / 1e3,
			description);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}


static int print_events(struct bpf_buffer *buf)
{
	int err;

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		return err;
	}

	time_since_start();
	printf("%-8s %-8s %-40s \n", "START", env.milliseconds ? "TIME (ms)" : "TIME (us)",
					"DESCRIPTION");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %s\n",
				strerror(-err));
			break;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

	return err;
}

static int attach_language_usdt(struct ugc_bpf *obj)
{
	int err = 0;
	char binary_path[PATH_MAX];
	struct bpf_link *link = NULL;

	if (env.language == LA_NONE)
		return 0;

	if (resolve_binary_path(lang_so(env.language), env.pid, binary_path,
				sizeof(binary_path))) {
		warning("get binary file path failed\n");
		return -1;
	}

	link = bpf_program__attach_usdt(obj->progs.trace_gc__begin_1,
					env.pid, binary_path,
					languages[env.language].name,
					languages[env.language].begin_probe[0],
					NULL);
	if (!link)
		goto out;
	obj->links.trace_gc__begin_1 = link;
	link = bpf_program__attach_usdt(obj->progs.trace_gc__end_1,
					env.pid, binary_path,
					languages[env.language].name,
					languages[env.language].end_probe[0],
					NULL);
	if (!link)
		goto out;
	obj->links.trace_gc__end_1 = link;

	if (env.language == LA_RUBY) {
		link = bpf_program__attach_usdt(obj->progs.trace_gc__begin_2,
						env.pid, binary_path,
						languages[env.language].name,
						languages[env.language].begin_probe[1],
						NULL);
		if (!link)
			goto out;
		obj->links.trace_gc__begin_2 = link;
		link = bpf_program__attach_usdt(obj->progs.trace_gc__end_2,
						env.pid, binary_path,
						languages[env.language].name,
						languages[env.language].end_probe[1],
						NULL);
		if (!link)
			goto out;
		obj->links.trace_gc__end_2 = link;
	}

out:
	if (!link) {
		err = errno;
		warning("attach usdt failed: %s\n", strerror(err));
		return -1;
	}
	return 0;
}

static void alias_parse(char *prog)
{
	char *name = basename(prog);

	if (!strcmp(name, "nodegc"))
		env.language = LA_NODE;
	else if (!strcmp(name, "pythongc"))
		env.language = LA_PYTHON;
	else if (!strcmp(name, "rubygc"))
		env.language = LA_RUBY;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct ugc_bpf *obj;
	struct bpf_buffer *buf = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	alias_parse(argv[0]);

	if (env.language == LA_NONE)
		str2language(detect_language(env.pid), &env.language);

	if (env.language == LA_NONE) {
		warning("Nothing to do; use -l to trace a language. \n");
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

	obj = ugc_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	obj->rodata->target_pid = env.pid;
	obj->rodata->target_language = env.language;
	obj->rodata->minimum = env.minimum * 1000000;

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer\n");
		err = -errno;
		goto cleanup;
	}

	err = ugc_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		goto cleanup;
	}

	err = attach_language_usdt(obj);
	if (err) {
		warning("Failed to attch BPF USDT programs\n");
		goto cleanup;
	}

	err = ugc_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF tracepoints programs\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Failed to set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing garbage collections in process %d (language: %s)... Ctrl-C to quit.\n",
	       env.pid, lang_str(env.language));

	err = print_events(buf);

cleanup:
	bpf_buffer__free(buf);
	ugc_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
