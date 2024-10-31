// SPDX-License-Identifier: GPL-2.0
#include "commons.h"
#include "tcptracer.h"
#include "tcptracer.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "map_helpers.h"
#include "compat.h"

#include <sys/resource.h>
#include <arpa/inet.h>

static volatile sig_atomic_t exiting;

const char *argp_program_version = "tcptracer 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"\ntcptracer: Trace TCP connections\n"
"\n"
"EXAMPLES:\n"
"    tcptracer             # trace all TCP connections\n"
"    tcptracer -t          # include timestamps\n"
"    tcptracer -p 181      # only trace PID 181\n"
"    tcptracer -U          # include UID\n"
"    tcptracer -u 1000     # only trace UID 1000\n"
"    tcptracer --C mappath # only trace cgroups in the map\n"
"    tcptracer --M mappath # only trace mount namespaces in the map\n";

static int get_uint(const char *arg, unsigned int *ret, unsigned int min,
		    unsigned int max)
{
	char *end;
	long val;

	errno = 0;
	val = strtoul(arg, &end, 10);
	if (errno) {
		warning("strtoul: %s: %s\n", arg, strerror(errno));
		return -1;
	} else if (end == arg || val < min || val > max) {
		return -1;
	}
	if (ret)
		*ret = val;
	return 0;
}

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "print-uid", 'U', NULL, 0, "Include UID on output" },
	{ "pid", 'p', "PID", 0, "Process PID to trace" },
	{ "uid", 'u', "UID", 0, "Process UID to trace" },
	{ "cgroupmap", 'C', "PATH", 0, "trace cgroups in this map" },
	{ "mntnsmap", 'M', "PATH", 0, "trace mount namespaces in this map" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static struct env {
	bool verbose;
	bool count;
	bool print_timestamp;
	bool print_uid;
	pid_t pid;
	uid_t uid;
} env = {
	.uid = (uid_t)-1
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
	case 'c':
		env.count = true;
		break;
	case 't':
		env.print_timestamp = true;
		break;
	case 'U':
		env.print_uid = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'u':
		if (get_uint(arg, &env.uid, 0, (uid_t)-2)) {
			warning("Invalid UID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'C':
		warning("Not implemented: --cgroupmap\n");
		break;
	case 'M':
		warning("Not implemented: --mntnsmap\n");
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

static void print_events_header()
{
	if (env.print_timestamp)
		printf("%-9s", "TIME(s)");
	if (env.print_uid)
		printf("%-7s ", "UID");
	printf("%s %-7s %-12s %-2s %-16s %-16s %-4s %-4s\n",
	       "T", "PID", "COMM", "IP", "SADDR", "DADDR", "SPORT", "DPORT");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event e;
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr x4;
		struct in6_addr x6;
	} s, d;

	if (data_sz < sizeof(e)) {
		warning("Packet too small\n");
		return 0;
	}

	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	if (e.af == AF_INET) {
		s.x4.s_addr = e.saddr_v4;
		d.x4.s_addr = e.daddr_v4;
	} else if (e.af == AF_INET6) {
		memcpy(&s.x6.s6_addr, &e.saddr_v6, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, &e.daddr_v6, sizeof(d.x6.s6_addr));
	} else {
		warning("Broken event: event->af=%d\n", e.af);
		return 1;
	}

	if (env.print_timestamp)
		printf("%-9.3f", time_since_start());

	if (env.print_uid)
		printf("%-7s ", get_uid_name(e.uid));

	char type = '-';
	switch (e.type) {
	case TCP_EVENT_TYPE_CONNECT:
		type = 'C';
		break;
	case TCP_EVENT_TYPE_ACCEPT:
		type = 'A';
		break;
	case TCP_EVENT_TYPE_CLOSE:
		type = 'X';
		break;
	}

	printf("%c %-7d %-12.12s %-2d %-16s %-16s %-4d %-4d\n",
	       type, e.pid, e.task, e.af == AF_INET ? 4 : 6,
	       inet_ntop(e.af, &s, src, sizeof(src)),
	       inet_ntop(e.af, &d, dst, sizeof(dst)),
	       ntohs(e.sport), ntohs(e.dport));

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
		.doc = argp_program_doc
	};
	struct tcptracer_bpf *obj;
	struct bpf_buffer *buf = NULL;
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

	obj = tcptracer_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Faile to create ring/perf buffer\n");
		err = -errno;
		goto cleanup;
	}

	if (env.pid)
		obj->rodata->filter_pid = env.pid;
	if (env.uid != (uid_t)-1)
		obj->rodata->filter_uid = env.uid;

	err = tcptracer_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcptracer_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %s\n", strerror(-err));
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

	print_events_header();

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	tcptracer_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
