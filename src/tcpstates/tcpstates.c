// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include <arpa/inet.h>
#include "btf_helpers.h"
#include "compat.h"
#include "tcpstates.h"
#include "tcpstates.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;

static struct env {
	bool emit_timestamp;
	short target_family;
	char *target_sports;
	char *target_dports;
	bool wide_output;
	bool verbose;
} env;

static const char *tcp_states[] = {
	[1] = "ESTABLISHED",
	[2] = "SYN_SENT",
	[3] = "SYN_RECV",
	[4] = "FIN_WAIT1",
	[5] = "FIN_WAIT2",
	[6] = "TIME_WAIT",
	[7] = "CLOSE",
	[8] = "CLOSE_WAIT",
	[9] = "LAST_ACK",
	[10] = "LISTEN",
	[11] = "CLOSING",
	[12] = "NEW_SYN_RECV",
	[13] = "UNKNOWN",
};

const char *argp_program_version = "tcpstates 1.0";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace TCP session state changes and durations.\n"
"\n"
"USAGE: tcpstates [-4] [-6] [-T] [-L lport] [-R dport]\n"
"\n"
"EXAMPLES:\n"
"    tcpstates                  # trace all TCP state changes\n"
"    tcpstates -T               # include timestamps\n"
"    tcpstates -L 80            # only trace local port 80\n"
"    tcpstates -D 80            # only trace remote port 80\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 family only" },
	{ "ipv6", '6', NULL, 0, "Trace IPv6 family only" },
	{ "wide", 'w', NULL, 0, "Wide column output (fits IPv6 addresses)" },
	{ "localport", 'L', "LPORT", 0, "Comma-separated list of local ports to trace." },
	{ "remoteport", 'R', "RPORT", 0, "Comma-separated list of remote ports to trace." },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'T':
		env.emit_timestamp = true;
		break;
	case '4':
		env.target_family = AF_INET;
		break;
	case '6':
		env.target_family = AF_INET6;
		break;
	case 'w':
		env.wide_output = true;
		break;
	case 'L':
	case 'R':
	{
		char *port = strtok(arg, ",");
		while (port) {
			safe_strtol(arg, 1, 65535, state);
			port = strtok(NULL, ",");
		}
		if (key == 'L')
			env.target_sports = strdup(arg);
		else
			env.target_dports = strdup(arg);
		break;
	}
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event e;
	char saddr[39], daddr[39];

	if (data_sz < sizeof(e)) {
		warning("Packet too small\n");
		return 0;
	}

	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	if (env.emit_timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%8s ", ts);
	}

	inet_ntop(e.family, &e.saddr, saddr, sizeof(saddr));
	inet_ntop(e.family, &e.daddr, daddr, sizeof(daddr));

	if (env.wide_output) {
		int family = e.family == AF_INET ? 4 : 6;

		printf("%-16llx %-7d %-16s %-2d %-39s %5d %-39s %-5d %-11s -> %-11s %.3f\n",
		       e.skaddr, e.pid, e.task, family, saddr, e.sport, daddr, e.dport,
		       tcp_states[e.oldstate], tcp_states[e.newstate],
		       (double)e.delta_us / 1000);
	} else {
		printf("%-16llx %-7d %-10.10s %-15s %-5d %-15s %-5d %-11s -> %-11s %.3f\n",
		       e.skaddr, e.pid, e.task, saddr, e.sport, daddr, e.dport,
		       tcp_states[e.oldstate], tcp_states[e.newstate],
		       (double)e.delta_us / 1000);
	}

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
	struct tcpstates_bpf *obj;
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

	obj = tcpstates_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF objects\n");
		return 1;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer\n");
		err = 1;
		goto cleanup;
	}

	obj->rodata->filter_by_sport = env.target_sports != NULL;
	obj->rodata->filter_by_dport = env.target_dports != NULL;
	obj->rodata->target_family = env.target_family;

	if (probe_tp_btf("inet_sock_set_state"))
		bpf_program__set_autoload(obj->progs.inet_sock_set_state_raw, false);
	else
		bpf_program__set_autoload(obj->progs.inet_sock_set_state, false);

	err = tcpstates_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (env.target_sports) {
		int port_map_fd = bpf_map__fd(obj->maps.sports);
		char *port = strtok(env.target_sports, ",");

		while (port) {
			int port_num = strtol(port, NULL, 10);
			bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
			port = strtok(NULL, ",");
		}
	}
	if (env.target_dports) {
		int port_map_fd = bpf_map__fd(obj->maps.dports);
		char *port = strtok(env.target_dports, ",");

		while (port) {
			int port_num = strtol(port, NULL, 10);
			bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
			port = strtok(NULL, ",");
		}
	}

	err = tcpstates_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffers\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.emit_timestamp)
		printf("%-8s ", "TIME(s)");

	if (env.wide_output)
		printf("%-16s %-7s %-16s %-2s %-39s %-5s %-39s %-5s %-11s -> %-11s %s\n",
		       "SKADDR", "PID", "COMM", "IP", "LADDR", "LPORT",
		       "RADDR", "RPORT", "OLDSTATE", "NEWSTATE", "MS");
	else
		printf("%-16s %-7s %-10s %-15s %-5s %-15s %-5s %-11s -> %-11s %s\n",
		       "SKADDR", "PID", "COMM", "LADDR", "LPORT",
		       "RADDR", "RPORT", "OLDSTATE", "NEWSTATE", "MS");

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
	tcpstates_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
