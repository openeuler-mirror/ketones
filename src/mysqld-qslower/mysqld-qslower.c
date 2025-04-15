// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "compat.h"
#include "uprobe_helpers.h"
#include "mysqld-qslower.h"
#include "mysqld-qslower.skel.h"
#include "btf_helpers.h"

static volatile sig_atomic_t exiting;

struct env {
	pid_t pid;
	float min_ns;
	bool verbose;
} env = {
	.pid = -1,
	.min_ns = 1000000,
};

const char *argp_program_version = "mysql-qslower 0.1";
const char *argp_program_bug_address = "Yuan Chen <chenyuan@kylinos.cn>";
const char argp_program_doc[] =
"traces queries served by a MySQL server.\n"
"\n"
"USAGE: mysqld-qslower PID [min_ms]\n"
"\n"
"EXAMPLES:\n"
"    mysqld-qslower 1218      # Tracing MySQL server queries for PID 1218 slower than 1 ms\n"
"    mysqld-qslower 1218 0.1  # Tracing MySQL server queries for PID 1218 slower than 0.1 ms\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
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
	case ARGP_KEY_ARG:
		if (state->arg_num == 0) {
			env.pid = argp_parse_pid(key, arg, state);
		} else if (state->arg_num == 1) {
			env.min_ns = argp_parse_float(key, arg, state) * 1000000;
		} else {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (env.pid == -1) {
			warning("mysqld-qslower: error: the following arguments are required: pid\n");
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

static int handle_event(void *ctx, void *data, size_t data_size)
{
	struct data_t *ev = data;
	double delta;

	delta = time_since_start();
	printf("%-14.6f %-8d %12.3f %s\n", delta, ev->pid,
		(float)(ev->delta) / 1000000, ev->query);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on cpu #%d!\n", lost_cnt, cpu);
}

static int attach_usdt(struct mysqld_qslower_bpf *obj)
{
	int err = 0;
	char binary_path[PATH_MAX];

	if (resolve_binary_path("", env.pid, binary_path, sizeof(binary_path)))
		return 1;

	obj->links.do_start = bpf_program__attach_usdt(obj->progs.do_start,
							env.pid, binary_path,
							"mysql", "query__start",
							NULL);
	if (!obj->links.do_start) {
		err = errno;
		warning("attach usdt query__start failed: %s\n", strerror(errno));
		return err;
	}

	obj->links.do_done = bpf_program__attach_usdt(obj->progs.do_done,
							env.pid, binary_path,
							"mysql", "query__done",
							NULL);
	if (!obj->links.do_done) {
		err = errno;
		warning("attach usdt query__done failed: %s\n", strerror(errno));
		return err;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	struct mysqld_qslower_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return 1;
	}

	obj = mysqld_qslower_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = 1;
		warning("Failed to create create/perf buffer");
		goto cleanup;
	}

	obj->rodata->min_ns = env.min_ns;
	obj->rodata->target_pid = env.pid;

	err = mysqld_qslower_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		goto cleanup;
	}

	err = attach_usdt(obj);
	if (err) {
		warning("Failed to attch BPF USDT programs\n");
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing MySQL server queries for PID %d slower than %f ms...\n",
		env.pid, env.min_ns / 1000000);
	printf("%-14s %-8s %12s %s\n", "TIME(s)", "PID", "MS", "QUERY");
	while (!exiting) {
		err = bpf_buffer__poll(buf, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %d\n", err);
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	mysqld_qslower_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}