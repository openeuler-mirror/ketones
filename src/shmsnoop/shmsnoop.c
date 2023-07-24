// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "shmsnoop.h"
#include "shmsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"

static volatile sig_atomic_t exiting;

static struct env {
	pid_t pid;
	pid_t tid;
	unsigned int duration;
	const char *name;
	bool verbose;
	bool emit_timestamp;
} env;

const char *argp_program_version = "shmsnoop 0.1";
const char *argp_program_bug_address = "Youling Tang <tangyouling@kylinos.cn>";
const char argp_program_doc[] =
"Trace shm*() syscalls.\n"
"\n"
"USAGE: shmsnoop [-h] [-T] [-x] [-p PID] [-d DURATION] [-t TID] [-n NAME]\n"
"\n"
"EXAMPLES:\n"
"    shmsnoop           # trace all shm*() syscalls\n"
"    shmsnoop -T        # include timestamps\n"
"    shmsnoop -p 181    # only trace PID 181\n"
"    shmsnoop -t 123    # only trace TID 123\n"
"    shmsnoop -d 10     # trace for 10 seconds only\n"
"    shmsnoop -n main   # only print process names containing \"main\"\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "tid", 't', "TID", 0, "Thread TID to trace" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "duration", 'd', "SECONDS", 0, "Duration to trace" },
	{ "name", 'n', "NAME", 0, "Trace process names containing this" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		env.tid = argp_parse_pid(key, arg, state);
		break;
	case 'T':
		env.emit_timestamp = true;
		break;
	case 'd':
		env.duration = argp_parse_long(key, arg, state);
		break;
	case 'n':
		env.name = arg;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
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

static char *sys_name(int sys_type)
{
	switch (sys_type) {
	case SYS_SHMGET:
		return "SHMGET";
	case SYS_SHMAT:
		return "SHMAT";
	case SYS_SHMDT:
		return "SHMDT";
	case SYS_SHMCTL:
		return "SHMCTL";
	default:
		return "N/A";
	}
}

static void shmflg_str(unsigned long flags, unsigned long type)
{
	int cnt = 0, len = 0;
	char flags_str[100] = {};

	if (!flags) {
		printf("\n");
		return;
	}

#define CHECK_SHM_FLAG(flags, value)						\
	if ((flags & value) == value) {						\
		len += snprintf(flags_str + len, sizeof(flags_str) - len,	\
				"%s", cnt ? "|" : "(");				\
		len += snprintf(flags_str + len, sizeof(flags_str) - len,	\
				"%s", #value);					\
		flags &= ~value;						\
		cnt++;								\
	}									\

	if (type == SYS_SHMGET) {
		CHECK_SHM_FLAG(flags, IPC_CREAT);
		CHECK_SHM_FLAG(flags, IPC_EXCL);
		CHECK_SHM_FLAG(flags, SHM_HUGETLB);
		CHECK_SHM_FLAG(flags, SHM_HUGE_2MB);
		CHECK_SHM_FLAG(flags, SHM_HUGE_1GB);
		CHECK_SHM_FLAG(flags, SHM_NORESERVE);
		CHECK_SHM_FLAG(flags, SHM_EXEC);
	} else if (type == SYS_SHMAT) {
		CHECK_SHM_FLAG(flags, SHM_RDONLY);
		CHECK_SHM_FLAG(flags, SHM_RND);
		CHECK_SHM_FLAG(flags, SHM_REMAP);
		CHECK_SHM_FLAG(flags, SHM_EXEC);
	}

	if (flags)
		len += snprintf(flags_str + len, sizeof(flags_str) - len,
				"%s0%lo", cnt ? "|" : "(",flags);
	printf(" %s)\n", flags_str);
}

static void print_args(const struct event *e)
{
	switch (e->sys) {
	case SYS_SHMGET:
		printf("key: 0x%lx, size: %lu, shmflg: 0x%lx", e->key, e->size, e->shmflg);
		shmflg_str(e->shmflg, e->sys);
		break;
	case SYS_SHMAT:
		printf("shmid: 0x%lx, shmaddr: 0x%lx, shmflg: 0x%lx", e->shmid, e->shmaddr, e->shmflg);
		shmflg_str(e->shmflg, e->sys);
		break;
	case SYS_SHMDT:
		printf("shmaddr: 0x%lx\n", e->shmaddr);
		break;
	case SYS_SHMCTL:
		printf("shmid: 0x%lx, cmd: %lu, buf: 0x%lx\n", e->shmid, e->cmd, e->buf);
		break;
	}

}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	/* name filtering is currently done in user space */
	if (env.name && strstr(e->comm, env.name) == NULL)
		return 0;

	if (env.emit_timestamp)
		printf("%-14.3f ", time_since_start());
	printf("%-6d %-16s %6s %16lx ", e->pid, e->comm, sys_name(e->sys), e->ret);
	print_args(e);

	return 0;
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
	struct bpf_buffer *buf = NULL;
	struct shmsnoop_bpf *obj;
	unsigned long long time_end = 0;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = shmsnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		warning("Failed to create ring/perf buffer\n");
		goto cleanup;
	}

	/* Init global data */
	obj->rodata->target_pid = env.pid;
	obj->rodata->target_tid = env.tid;

	if (!tracepoint_exists("syscalls", "sys_enter_shmat")) {
		bpf_program__set_autoload(obj->progs.handle_shmat_entry, false);
		bpf_program__set_autoload(obj->progs.handle_shmat_return, false);
	}

	if (!tracepoint_exists("syscalls", "sys_enter_shmctl")) {
		bpf_program__set_autoload(obj->progs.handle_shmctl_entry, false);
		bpf_program__set_autoload(obj->progs.handle_shmctl_return, false);
	}

	if (!tracepoint_exists("syscalls", "sys_enter_shmdt")) {
		bpf_program__set_autoload(obj->progs.handle_shmdt_entry, false);
		bpf_program__set_autoload(obj->progs.handle_shmdt_return, false);
	}

	if (!tracepoint_exists("syscalls", "sys_enter_shmget")) {
		bpf_program__set_autoload(obj->progs.handle_shmget_entry, false);
		bpf_program__set_autoload(obj->progs.handle_shmget_return, false);
	}

	err = shmsnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = shmsnoop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	if (env.emit_timestamp)
		printf("%-14s ", "TIME(s)");
	if(env.tid)
		printf("%-6s ", "TID");
	else
		printf("%-6s ", "PID");
	printf("%-16s %6s %16s %-s\n", "COMM", "SYS", "RET", "ARGs");

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

	/* Loop */
	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		if (env.duration && get_ktime_ns() > time_end)
			goto cleanup;

		/* retset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	shmsnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
