// SPDX-License-Identifier: GPL-2.0
#include "commons.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "tcplife.h"
#include "tcplife.skel.h"
#include "compat.h"

#include <arpa/inet.h>

static volatile sig_atomic_t exiting;

static struct env {
	pid_t	target_pid;
	short	target_family;
	__u16	target_sports[MAX_PORTS];
	bool	filter_sport;
	__u16	target_dports[MAX_PORTS];
	bool	filter_dport;
	int	column_width;
	bool	emit_timestamp;
	bool	verbose;
} env = {
	.column_width = 15,
};

const char *argp_program_version = "tcplife 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace the lifespan of TCP sessions and summarize.\n"
"\n"
"USAGE: tcplife [-h] [-p PID] [-4] [-6] [-L] [-R] [-T] [-w]\n"
"\n"
"EXAMPLES:\n"
"    tcplife -p 1215             # only trace PID 1215\n"
"    tcplife -p 1215 -4          # trace IPv4 only\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 only" },
	{ "ipv6", '6', NULL, 0, "Trace IPv6 only" },
	{ "wide", 'w', NULL, 0, "Wide column output (fits IPv6 addesses)" },
	{ "time", 'T', NULL, 0, "Include timestamp on output" },
	{ "localport", 'L', "LOCALPORT", 0, "Comma-separated list of local ports to trace." },
	{ "remoteport", 'R', "REMOTEPORT", 0, "Comma-separated list of remote ports to trace." },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		env.target_pid = argp_parse_pid(key, arg, state);
		break;
	case '4':
		env.target_family = AF_INET;
		break;
	case '6':
		env.target_family = AF_INET6;
		break;
	case 'w':
		env.column_width = 26;
		break;
	case 'L':
	case 'R':
	{
		char *port = strtok(arg, ",");

		for (int i = 0; i < MAX_PORTS && port; i++) {
			if (key == 'L')
				env.target_sports[i] = safe_strtol(port, 1, 65535, state);
			else
				env.target_dports[i] = safe_strtol(port, 1, 63355, state);
			port = strtok(NULL, ",");
		}
		break;
	}
	case 'T':
		env.emit_timestamp = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_END:
		if (env.target_sports[0] != 0)
			env.filter_sport = true;
		if (env.target_dports[0] != 0)
			env.filter_dport = true;
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];

	if (env.emit_timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%8s ", ts);
	}

	inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
	inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));

	printf("%-7d %-16s %-*s %-5d %-*s %-5d %-6.2f %-6.2f %-.2f\n",
	       e->pid, e->comm, env.column_width, saddr, e->sport,
	       env.column_width, daddr, e->dport,
	       (double)e->tx_b / 1024, (double)e->rx_b / 1024,
	       (double)e->span_us / 1000);

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
		warning("Failed to open ring/perf buffer\n");
		return err;
	}

	if (env.emit_timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-7s %-16s %-*s %-5s %-*s %-5s %-6s %-6s %-s\n",
	       "PID", "COMM", env.column_width, "LADDR", "LPORT",
	       env.column_width, "RADDR", "RPORT", "TX_KB", "RX_KB", "MS");

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
	struct tcplife_bpf *obj;
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

	obj = tcplife_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		err = 1;
		goto cleanup;
	}

	obj->rodata->target_pid = env.target_pid;
	obj->rodata->target_family = env.target_family;
	obj->rodata->filter_sport = env.filter_sport;
	obj->rodata->filter_dport = env.filter_dport;

	for (int i = 0; i < MAX_PORTS; i++) {
		obj->rodata->target_dports[i] = env.target_dports[i];
		obj->rodata->target_sports[i] = env.target_sports[i];
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		warning("Failed to create ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (probe_tp_btf("inet_sock_set_state"))
		bpf_program__set_autoload(obj->progs.inet_sock_set_state_raw, false);
	else
		bpf_program__set_autoload(obj->progs.inet_sock_set_state, false);

	err = tcplife_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcplife_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	err = print_events(buf);

cleanup:
	bpf_buffer__free(buf);
	tcplife_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
