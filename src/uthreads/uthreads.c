// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on uthreads.py - Sasha Goldshtein

#include "commons.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"
#include "trace_helpers.h"
#include "compat.h"
#include "uthreads.h"
#include "uthreads.skel.h"
#include <libgen.h>

static struct {
        bool verbose;
        enum LANGUAGE language;
        pid_t pid;
} env = {
        .pid = -1,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "uthreads 0.1";
const char *argp_program_bug_address = "Yun Lu <luyun@kylinos.cn>";
const char argp_program_doc[] =
"Trace thread creation/destruction events in high-level languages.\n"
"\n"
"USAGE: uthreads [-h] [-l {c,java,none}] [-v] pid\n"
"Examples:\n"
"    ./uthreads -l java 185    # trace Java threads in process 185\n"
"    ./uthreads -l none 12245  # trace only pthreads in process 12245\n";

const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "language", 'l', "LANGUAGE", 0, "language to trace [c,java,none]", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "show the help", 0 },
	{}
};

struct syms_cache *syms_cache = NULL;

static bool str2language(const char *la_str, enum LANGUAGE *language)
{
	if (!la_str) {
		*language = LA_NONE;
		return true;
	}

	if (!strcmp(la_str, "java"))
		*language = LA_JAVA;
        else if (!strcmp(la_str, "c"))
		*language = LA_C;
        else if (!strcmp(la_str, "none"))
		*language = LA_C;
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

static void alias_parse(char *prog)
{
	char *name = basename(prog);

	if (!strcmp(name, "javathreads"))
		env.language = LA_JAVA;

}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct thread_event_t *te = data;
	const struct syms *syms;
	const struct sym *sym;
	char tid[64];

	if (!strcmp(te->type, "pthread")) {
		syms = syms_cache__get_syms(syms_cache, env.pid);
		if (syms) {
			sym = syms__map_addr(syms, te->runtime_id);
			if (sym) {
				printf("%-8.3f %-16ld %-8s %-30s\n", time_since_start(),
						te->native_id, te->type, sym->name);
				return 0;
			}
			else
				warning("Failed to syms__map\n");
		} else
			warning("Failed to get syms\n");
	} else {
		sprintf(tid, "R=%ld/N=%ld", te->runtime_id, te->native_id);
		printf("%-8.3f %-16s %-8s %-30s\n", time_since_start(),
				tid, te->type, te->name);
	}

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
	printf("%-8s %-16s %-8s %-30s \n", "TIME", "ID", "TYPE", "DESCRIPTION");

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

static const char *lang_so(enum LANGUAGE language)
{
	switch (language) {
	case LA_C: return "c";
	case LA_JAVA: return "jvm";
	default: return "unknow";
	}
	return NULL;
}

static int attach_language_usdt(struct uthreads_bpf *obj)
{
	int err = 0;
	char binary_path[PATH_MAX];

	if (env.language == LA_NONE)
		return 0;

	err = resolve_binary_path(lang_so(env.language), env.pid, binary_path,
					sizeof(binary_path));
	if (err < 0) {
		warning("get binary file path failed\n");
		return -1;
	}

	if (env.language == LA_JAVA) {
		obj->links.trace_start = bpf_program__attach_usdt(obj->progs.trace_start,
								  env.pid, binary_path,
								  "hotspot", "thread__start",
								  NULL);
		if (!obj->links.trace_start) {
			err = errno;
			warning("attach usdt thread__start failed: %s\n", strerror(errno));
			return err;
		}

		obj->links.trace_stop = bpf_program__attach_usdt(obj->progs.trace_stop,
								 env.pid, binary_path,
								 "hotspot", "thread__stop",
								 NULL);
		if (!obj->links.trace_stop) {
			err = errno;
			warning("attach usdt thread__stop failed: %s\n", strerror(errno));
			return err;
		}
	} else {
		obj->links.trace_pthread = bpf_program__attach_usdt(obj->progs.trace_pthread,
								    env.pid, binary_path,
								    "libc", "pthread_start",
								    NULL);
		if (!obj->links.trace_pthread) {
			err = errno;
			warning("attach usdt pthread_start failed: %s\n", strerror(errno));
			return err;
		}
	}

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
	struct uthreads_bpf *obj;
	struct bpf_buffer *buf = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	alias_parse(argv[0]);

	if (env.language == LA_NONE)
		str2language(detect_language(env.pid), &env.language);

	if (env.language == LA_NONE) {
		warning("Nothing to do; use -l to trace language.\n");
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

	obj = uthreads_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	if (env.language == LA_JAVA) {
		bpf_program__set_autoload(obj->progs.trace_pthread, false);
	} else {
		bpf_program__set_autoload(obj->progs.trace_start, false);
		bpf_program__set_autoload(obj->progs.trace_stop, false);
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer\n");
		err = -errno;
		goto cleanup;
	}

	err = uthreads_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		goto cleanup;
	}

	err = attach_language_usdt(obj);
	if (err) {
		warning("Failed to attch BPF USDT programs\n");
		goto cleanup;
	}

	err = uthreads_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF tracepoints programs\n");
		goto cleanup;
	}

	if (env.language == LA_C) {
		syms_cache = syms_cache__new(0);
		if (!syms_cache) {
			warning("Failed to create syms_cache\n");
			goto cleanup;
		}
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Failed to set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing thread events in process %d (language: %s)... Ctrl-C to quit.\n",
	       env.pid, env.language == LA_JAVA ? "java" : "c");

	err = print_events(buf);

cleanup:
	bpf_buffer__free(buf);
	syms_cache__free(syms_cache);
	uthreads_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
