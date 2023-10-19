// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "sofdsnoop.h"
#include "sofdsnoop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;

static struct env {
	__u32 pid;
	__u32 tid;
	char name[TASK_COMM_LEN];
	bool timestamp;
	__u64 duration;
	bool verbose;
} env;

const char *argp_program_version = "sofdsnoop 0.1";
const char *argp_program_bug_address = "Yuan Chen <chenyuan@kylinos.cn>";
const char argp_program_doc[] =
"sofdsnoop traces FDs passed through unix sockets\n"
"\n"
"usage: sofdsnoop [-h] [-T] [-p PID] [-t TID] [-n NAME] [-d DURATION]\n"
"\n"
"examples:\n"
"./sofdsnoop           # trace passed file descriptors\n"
"./sofdsnoop -T        # include timestamps\n"
"./sofdsnoop -p 181    # only trace PID 181\n"
"./sofdsnoop -t 123    # only trace TID 123\n"
"./sofdsnoop -d 10     # trace for 10 seconds only\n"
"./sofdsnoop -n main   # only print process names containing \"main\"";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "timestamp", 'T', NULL, 0, "include timestamp on output" },
	{ "pid", 'p', "PID", 0, "trace this PID only" },
	{ "tid", 't', "TID", 0, "trace this TID only" },
	{ "name", 'n', "NAME", 0, "only print process names containing this name"},
	{ "duration", 'd', "DURATION", 0, "total duration of trace in seconds"},
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
	{}
};

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
		env.timestamp = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		env.tid = argp_parse_long(key, arg, state);
		break;
	case 'n':
		strncpy(env.name, arg, sizeof(env.name));
		break;
	case 'd':
		env.duration = argp_parse_long(key, arg, state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const char *syscall_prefixes[] = {
	"sys_",
	"__x64_sys_",
	"__arm64_sys_",
	"__x32_compat_sys_",
	"__ia32_compat_sys_",
	"__s390x_sys_",
	"__s390_sys_",
};

static char *get_syscall_func_name(char *name)
{
	char buf[128] = {0};
	int i;

	for (i = 0; i < ARRAY_SIZE(syscall_prefixes); i++) {
		snprintf(buf, sizeof(buf), "%s%s", syscall_prefixes[i], name);
		if (kprobe_exists(buf))
			return strdup(buf);
	}

	return NULL;
}

static int attach_progs(struct sofdsnoop_bpf *obj)
{
	struct bpf_link *link = NULL;
	char *send_func = get_syscall_func_name("sendmsg");
	char *recv_func = get_syscall_func_name("recvmsg");
	int err = -1;

	if (!send_func || !recv_func) {
		warning("get syscall name of sendmsg or recvmsg failed.\n");
		return err;
	}

	link = bpf_program__attach_kprobe(obj->progs.syscall__sendmsg,
					  false, send_func);
	if (!link) {
		warning("attach %s kprobe attach failed\n", send_func);
		goto cleanup;
	}

	link = bpf_program__attach_kprobe(obj->progs.trace_sendmsg_return,
					  true, send_func);
	if (!link) {
		warning("attach %s kretprobe attach failed\n", send_func);
		goto cleanup;
	}

	link = bpf_program__attach_kprobe(obj->progs.syscall__recvmsg,
					  false, recv_func);
	if (!link) {
		warning("attach %s kprobe attach failed\n", recv_func);
		goto cleanup;
	}

	link = bpf_program__attach_kprobe(obj->progs.trace_recvmsg_return,
					  true, recv_func);
	if (!link) {
		warning("attach %s kretprobe attach failed\n", recv_func);
		goto cleanup;
	}

	err = sofdsnoop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}
	err = 0;

cleanup:
	free(send_func);
	free(recv_func);
	return err;
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

static char *get_file(__u32 pid, int fd)
{
	char path[PATH_MAX] = {0};
	char buf[512] = {0};
	ssize_t n;

	snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
	n = readlink(path, buf, sizeof(buf));
	if (n < 0)
		return NULL;

	return strdup(buf);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_size)
{
	struct val_t *ev = data;
	__u32 tid = ev->id & 0xffffffff;
	int cnt, i, fd;
	char *fd_file = NULL;
	char *sock_file;
	char buf[512] = {0};

	cnt = min(MAX_FD, ev->fd_cnt);
	if (env.name[0] != '\0' && strstr(env.name, ev->comm))
		return;

	for (i = 0; i < cnt; i++) {
		if (env.timestamp)
			printf("%-14.9f", time_since_start());

		printf("%-6s %-6d %-16s ", ev->action == ACTION_SEND ? "SEND" : "RECV",
			tid, ev->comm);

		sock_file = get_file(tid, ev->sock_fd);
		snprintf(buf, sizeof(buf), "%d:%s", ev->sock_fd, sock_file ? sock_file : "N/A");
		printf("%-25s ", buf);
		if (sock_file)
			free(sock_file);

		fd = ev->fd[i];
		if (ev->action == ACTION_SEND)
			fd_file = get_file(tid, fd);

		printf("%-5d %s\n", fd, fd_file ? fd_file : "N/A");
		if (fd_file)
			free(fd_file);
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on cpu #%d!\n", lost_cnt, cpu);
}

static void print_header(void)
{
	if (env.timestamp)
		printf("%-14s", "TIME(s)");
	printf("%-6s %-6s %-16s %-25s %-5s %s\n", "ACTION", "TID",
		"COMM", "SOCKET", "FD", "NAME");
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
	struct sofdsnoop_bpf *obj = NULL;
	double start;
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

	obj = sofdsnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->g_pid = env.pid;
	obj->rodata->g_tid = env.tid;

	err = sofdsnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = attach_progs(obj);
	if (err) {
		warning("Failed to attch BPF kprobe programs\n");
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warning("Failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	print_header();
	start = time_since_start();
	while (!exiting) {
		if (env.duration) {
			if (time_since_start() - start > env.duration)
				break;
		}

		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling perf buffer: %d\n", err);
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	sofdsnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
