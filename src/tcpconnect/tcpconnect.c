// SPDX-License-Identifier: GPL-2.0
#include "commons.h"
#include "tcpconnect.h"
#include "tcpconnect.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"
#include "map_helpers.h"
#include <arpa/inet.h>
#include <pwd.h>

static volatile sig_atomic_t exiting;

const char *argp_program_version = "tcpconnect 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"\ntcpconnect: Count/Trace active tcp connections\n"
"\n"
"EXAMPLES:\n"
"    tcpconnect             # trace all TCP connect()s\n"
"    tcpconnect -t          # include timestamps\n"
"    tcpconnect -p 181      # only trace PID 181\n"
"    tcpconnect -P 80       # only trace port 80\n"
"    tcpconnect -P 80,81    # only trace port 80 and 81\n"
"    tcpconnect -U          # include UID\n"
"    tcpconnect -u 1000     # only trace UID 1000\n"
"    tcpconnect -c          # count connects per src, dest, port\n"
"    tcpconnect --C mappath # only trace cgroups in the map\n"
"    tcpconnect --M mappath # only trace mount namespaces in the map\n"
;

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "count", 'c', NULL, 0, "Count connects per src ip and dst ip/port" },
	{ "print-uid", 'U', NULL, 0, "Include UID on output" },
	{ "pid", 'p', "PID", 0, "Process PID to trace" },
	{ "uid", 'u', "UID", 0, "Process UID to trace" },
	{ "source-port", 's', NULL, 0, "Consider source port when counting" },
	{ "port", 'P', "PORTS", 0,
	  "Comma-separated list of destination ports to trace" },
	{ "cgroupmap", 'C', "PATH", 0, "Trace cgroups in this map" },
	{ "mntnsmap", 'M', "PATH", 0, "Trace mount namespaces in this map" },
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
	int nports;
	int ports[MAX_PORTS];
	bool source_port;
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
	case 's':
		env.source_port = true;
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
		env.uid = safe_strtoul(arg, 0, (uid_t)-2, state);
		break;
	case 'P':
	{
		char *port = strtok(arg, ",");

		for (int i = 0; port; i++) {
			env.ports[i] = safe_strtol(port, 1, 65535, state);
			env.nports++;

			port = strtok(NULL, ",");
		}
		break;
	}
	case 'C':
		warning("Not implemented: --cgroupmap");
		break;
	case 'M':
		warning("Not implemented: --mntnsmap");
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

static void print_count_ipv4(int map_fd)
{
	static struct ipv4_flow_key keys[MAX_ENTRIES];
	__u32 value_size = sizeof(__u64);
	__u32 key_size = sizeof(keys[0]);
	static struct ipv4_flow_key zero;
	static __u64 counts[MAX_ENTRIES];
	char s[INET_ADDRSTRLEN];
	char d[INET_ADDRSTRLEN];
	__u32 n = MAX_ENTRIES;
	struct in_addr src, dst;

	if (dump_hash(map_fd, keys, key_size, counts, value_size, &n, &zero)) {
		warning("Dump_hash: %s", strerror(errno));
		return;
	}

	for (int i = 0; i < n; i++) {
		src.s_addr = keys[i].saddr;
		dst.s_addr = keys[i].daddr;

		printf("%-25s %-25s",
		       inet_ntop(AF_INET, &src, s, sizeof(s)),
		       inet_ntop(AF_INET, &dst, d, sizeof(d)));
		if (env.source_port)
			printf(" %-20d", keys[i].sport);
		printf(" %-20d", ntohs(keys[i].dport));
		printf(" %-10llu", counts[i]);
		printf("\n");
	}
}

static void print_count_ipv6(int map_fd)
{
	static struct ipv6_flow_key keys[MAX_ENTRIES];
	__u32 value_size = sizeof(__u64);
	__u32 key_size = sizeof(keys[0]);
	static struct ipv6_flow_key zero;
	static __u64 counts[MAX_ENTRIES];
	char s[INET6_ADDRSTRLEN];
	char d[INET6_ADDRSTRLEN];
	struct in6_addr src, dst;
	__u32 n = MAX_ENTRIES;

	if (dump_hash(map_fd, keys, key_size, counts, value_size, &n, &zero)) {
		warning("dump_hash: %s\n", strerror(errno));
		return;
	}

	for (int i = 0; i < n; i++) {
		memcpy(src.s6_addr, keys[i].saddr, sizeof(src.s6_addr));
		memcpy(dst.s6_addr, keys[i].daddr, sizeof(dst.s6_addr));

		printf("%-25s %-25s",
		       inet_ntop(AF_INET6, &src, s, sizeof(s)),
		       inet_ntop(AF_INET6, &dst, d, sizeof(d)));
		if (env.source_port)
			printf(" %-20d", keys[i].sport);
		printf(" %-20d", ntohs(keys[i].dport));
		printf(" %-10llu", counts[i]);
		printf("\n");
	}
}

static void print_count_header(void)
{
	printf("\n%-25s %-25s", "LADDR", "RADDR");
	if (env.source_port)
		printf(" %-20s", "LPORT");
	printf(" %-20s", "RPORT");
	printf(" %-10s", "CONNECTS");
	printf("\n");
}

static void print_count(int map_fd_ipv4, int map_fd_ipv6)
{
	while (!exiting)
		pause();

	print_count_header();
	print_count_ipv4(map_fd_ipv4);
	print_count_ipv6(map_fd_ipv6);
}

static void print_events_headers(void)
{
	if (env.print_timestamp)
		printf("%-9s ", "TIME(s)");
	if (env.print_uid)
		printf("%-7s ", "UID");
	printf("%-7s %-16s %-2s %-25s %-25s",
	       "PID", "COMM", "IP", "SADDR", "DADDR");
	if (env.source_port)
		printf(" %-5s", "SPORT");
	printf(" %-5s\n", "DPORT");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *event = data;
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;

	if (event->af == AF_INET) {
		s.x4.s_addr = event->saddr_v4;
		d.x4.s_addr = event->daddr_v4;
	} else if (event->af == AF_INET6) {
		memcpy(&s.x6.s6_addr, event->saddr_v6, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, event->daddr_v6, sizeof(d.x6.s6_addr));
	} else {
		warning("Broken event: event->af=%d\n", event->af);
		return 0;
	}

	if (env.print_timestamp)
		printf("%-9.3f ", time_since_start());

	if (env.print_uid) {
		struct passwd *passwd;
		passwd = getpwuid(event->uid);
		if (!passwd) {
			warning("getpwuid() failed: %s\n", strerror(errno));
			return -1;
		}
		printf("%-7s ", passwd->pw_name);
	}

	printf("%-7d %-16.16s %-2d %-25s %-25s",
	       event->pid, event->task,
	       event->af == AF_INET ? 4 : 6,
	       inet_ntop(event->af, &s, src, sizeof(src)),
	       inet_ntop(event->af, &d, dst, sizeof(dst)));

	if (env.source_port)
		printf(" %-5d", event->sport);

	printf(" %-5d", ntohs(event->dport));
	printf("\n");

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

	print_events_headers();

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %s\n", strerror(-err));
			break;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

	return err;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct tcpconnect_bpf *obj;
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

	obj = tcpconnect_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF objects\n");
		err = 1;
		goto cleanup;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer\n");
		err = -errno;
		goto cleanup;
	}

	if (env.count)
		obj->rodata->do_count = true;
	if (env.pid)
		obj->rodata->filter_pid = env.pid;
	if (env.uid != (uid_t)-1)
		obj->rodata->filter_uid = env.uid;
	if (env.nports > 0) {
		obj->rodata->filter_ports_len = env.nports;
		for (int i = 0; i < env.nports; i++)
			obj->rodata->filter_ports[i] = htons(env.ports[i]);
	}
	if (env.source_port)
		obj->rodata->source_port = true;

	if (fentry_can_attach("tcp_v4_connect", NULL)) {
		bpf_program__set_autoload(obj->progs.tcp_v4_connect_kprobe, false);
		bpf_program__set_autoload(obj->progs.tcp_v6_connect_kprobe, false);
		bpf_program__set_autoload(obj->progs.tcp_v4_connect_ret_kprobe, false);
		bpf_program__set_autoload(obj->progs.tcp_v6_connect_ret_kprobe, false);
	} else {
		bpf_program__set_autoload(obj->progs.tcp_v4_connect, false);
		bpf_program__set_autoload(obj->progs.tcp_v6_connect, false);
		bpf_program__set_autoload(obj->progs.tcp_v4_connect_ret, false);
		bpf_program__set_autoload(obj->progs.tcp_v6_connect_ret, false);
	}

	err = tcpconnect_bpf__load(obj);
	if (err) {
		warning("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcpconnect_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.count) {
		print_count(bpf_map__fd(obj->maps.ipv4_count),
			    bpf_map__fd(obj->maps.ipv6_count));
	} else {
		err = print_events(buf);
	}

cleanup:
	tcpconnect_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
