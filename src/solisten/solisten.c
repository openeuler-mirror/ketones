// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "solisten.h"
#include "solisten.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"

#include <sys/socket.h>
#include <arpa/inet.h>

static volatile sig_atomic_t exiting;

static pid_t target_pid = 0;
static bool emit_timestamp = false;
static bool verbose = false;

const char *argp_program_version = "solisten 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace IPv4 and IPv6 listen syscalls.\n"
"\n"
"USAGE: solisten [-h] [-t] [-p PID]\n"
"\n"
"EXAMPLES:\n"
"    solisten           # trace listen syscalls\n"
"    solisten -t        # output with timestamp\n"
"    solisten -p 1216   # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		target_pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		emit_timestamp = true;
		break;
	case 'v':
		verbose = true;
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
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char proto[16], addr[48] = {};
	__u16 family = e->proto >> 16;
	__u16 type = (__u16)e->proto;
	const char *prot;

	if (emit_timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%8s ", ts);
	}

	if (type == SOCK_STREAM)
		prot = "TCP";
	else if (type == SOCK_DGRAM)
		prot = "UDP";
	else
		prot = "UNK";
	if (family == AF_INET)
		snprintf(proto, sizeof(proto), "%sv4", prot);
	else
		snprintf(proto, sizeof(proto), "%sv6", prot);
	inet_ntop(family, e->addr, addr, sizeof(addr));
	printf("%-7d %-16s %-3d %-7d %-5s %-5d %-32s\n",
	       e->pid, e->task, e->ret, e->backlog, proto, e->port, addr);

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
	struct solisten_bpf *obj;
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

	obj = solisten_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;

	if (fentry_can_attach("inet_listen", NULL)) {
		bpf_program__set_autoload(obj->progs.inet_listen_entry, false);
		bpf_program__set_autoload(obj->progs.inet_listen_exit, false);
	} else {
		bpf_program__set_autoload(obj->progs.inet_listen_fexit, false);
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer\n");
		err = -errno;
		goto cleanup;
	}

	err = solisten_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer\n");
		goto cleanup;
	}

	err = solisten_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (emit_timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-7s %-16s %-3s %-7s %-5s %-5s %-32s\n",
	       "PID", "COMM", "RET", "BACKLOG", "PROTO", "PORT", "ADDR");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling perf buffer: %s\n", strerror(-err));
			break;
		}

		/* retset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	solisten_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
