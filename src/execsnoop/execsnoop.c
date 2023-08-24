// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "execsnoop.skel.h"
#include "execsnoop.h"
#include "trace_helpers.h"
#include "btf_helpers.h"

#define MAX_ARGS_KEY		259

static volatile sig_atomic_t exiting;

static struct env {
	bool time;
	bool timestamp;
	bool fails;
	uid_t uid;
	bool quote;
	const char *name;
	const char *line;
	bool print_uid;
	bool verbose;
	int max_args;
	char *cgroupspath;
	bool cg;
} env = {
	.max_args = DEFAULT_MAX_ARGS,
	.uid = INVALID_UID
};

const char *argp_program_version = "execsnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace exec syscalls\n"
"\n"
"USAGE: execsnoop [-h] [-T] [-t] [-x] [-u UID] [-q] [-n NAME] [-l LINE] [-U] [-c CG]\n"
"                 [--max-args MAX_ARGS]\n"
"\n"
"EXAMPLES:\n"
"   ./execsnoop           # trace all exec() syscalls\n"
"   ./execsnoop -x        # include failed exec()s\n"
"   ./execsnoop -T        # include time (HH:MM:SS)\n"
"   ./execsnoop -U        # include UID\n"
"   ./execsnoop -u 1000   # only trace UID 1000\n"
"   ./execsnoop -t        # include timestamps\n"
"   ./execsnoop -q        # add \"quotemarks\" around arguments\n"
"   ./execsnoop -n main   # only print command lines containing \"main\"\n"
"   ./execsnoop -l tpkg   # only print command where arguments contains \"tpkg\"\n"
"   ./execsnoop -c CG     # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "time", 'T', NULL, 0, "Include time colum on output (HH:MM:SS)" },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "fails", 'x', NULL, 0, "Include failed exec()s" },
	{ "uid", 'u', "UID", 0, "Trace this UID only" },
	{ "quote", 'q', NULL, 0, "Add quotemarks (\") around arguments" },
	{ "name", 'n', "NAME", 0, "only print commands matching this name, any arg" },
	{ "line", 'l', "LINE", 0, "only print commands where arg contains this line" },
	{ "print-uid", 'U', NULL, 0, "print UID column" },
	{ "max-args", MAX_ARGS_KEY, "MAX_ARGS", 0,
		"maximum number of arguments parsed and displayed, default to 20" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long int uid, max_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'T':
		env.time = true;
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'x':
		env.fails = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'u':
		errno = 0;
		uid = strtol(arg, NULL, 10);
		if (errno) {
			warning("Invalid UID %s\n", arg);
			argp_usage(state);
		}
		env.uid = uid;
		break;
	case 'q':
		env.quote = true;
		break;
	case 'n':
		env.name = arg;
		break;
	case 'l':
		env.line = arg;
		break;
	case 'U':
		env.print_uid = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case MAX_ARGS_KEY:
		errno = 0;
		max_args = strtol(arg, NULL, 10);
		if (errno || max_args < 1 || max_args > TOTAL_MAX_ARGS) {
			warning("Invalid MAX_ARGS %s, should be in [1, %d] range\n",
				arg, TOTAL_MAX_ARGS);
			argp_usage(state);
		}
		env.max_args = max_args;
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

static void inline quoted_symbol(char c)
{
	switch (c) {
	case '"':
		putchar('\\');
		putchar('"');
		break;
	case '\t':
		putchar('\\');
		putchar('t');
		break;
	case '\n':
		putchar('\\');
		putchar('n');
		break;
	default:
		putchar(c);
		break;
	}
}

static void print_args(const struct event *e, bool quote)
{
	int args_counter = 0;

	if (env.quote)
		putchar('"');

	for (int i = 0; i < e->args_size && args_counter < e->args_count; i++) {
		char c = e->args[i];

		if (env.quote) {
			if (c == '\0') {
				args_counter++;
				putchar('"');
				putchar(' ');
				if (args_counter < e->args_count)
					putchar('"');
			} else {
				quoted_symbol(c);
			}
		} else {
			if (c == '\0') {
				args_counter++;
				putchar(' ');
			} else {
				putchar(c);
			}
		}
	}

	if (e->args_count == env.max_args + 1)
		fputs(" ...", stdout);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	char ts[32];

	if (env.name && strstr(e->comm, env.name) == NULL)
		return;
	if (env.line && strstr(e->comm, env.line) == NULL)
		return;

	strftime_now(ts, sizeof(ts), "%H:%M:%S");

	if (env.time)
		printf("%-8s ", ts);

	if (env.timestamp)
		printf("%-8.3f", time_since_start());

	if (env.print_uid)
		printf("%-6d ", e->uid);

	printf("%-16s %-7d %-7d %3d ", e->comm, e->pid, e->ppid, e->retval);
	print_args(e, env.quote);
	putchar('\n');
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct perf_buffer *pb = NULL;
	struct execsnoop_bpf *bpf_obj;
	int err, cgfd;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch neccessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	bpf_obj = execsnoop_bpf__open_opts(&open_opts);
	if (!bpf_obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	/* Init global data (filtering options) */
	bpf_obj->rodata->ignore_failed = !env.fails;
	bpf_obj->rodata->target_uid = env.uid;
	bpf_obj->rodata->max_args = env.max_args;
	bpf_obj->rodata->filter_memcg = env.cg;

	if (!tracepoint_exists("syscalls", "sys_enter_execve")) {
		bpf_program__set_autoload(bpf_obj->progs.tracepoint_syscall_enter_execve, false);
		bpf_program__set_autoload(bpf_obj->progs.tracepoint_syscall_exit_execve, false);
	}

	if (!tracepoint_exists("syscalls", "sys_enter_execveat")) {
		bpf_program__set_autoload(bpf_obj->progs.tracepoint_syscall_enter_execveat, false);
		bpf_program__set_autoload(bpf_obj->progs.tracepoint_syscall_exit_execveat, false);
	}

	err = execsnoop_bpf__load(bpf_obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (env.cg) {
		int idx = 0;
		int cg_map_fd = bpf_map__fd(bpf_obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			warning("Failed opening Cgroup path: %s\n", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			warning("Failed adding target cgroup to map\n");
			goto cleanup;
		}
	}

	err = execsnoop_bpf__attach(bpf_obj);
	if (err) {
		warning("Failed to attach BPF programs\n");
		goto cleanup;
	}

	if (env.time)
		printf("%-9s", "TIME");
	if (env.timestamp)
		printf("%-8s ", "TIME(s)");
	if (env.print_uid)
		printf("%-6s ", "UID");

	printf("%-16s %-7s %-7s %3s %s\n", "PCOMM", "PID", "PPID", "RET", "ARGS");

	pb = perf_buffer__new(bpf_map__fd(bpf_obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warning("Failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* Loop */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}

		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	execsnoop_bpf__destroy(bpf_obj);
	cleanup_core_btf(&open_opts);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
