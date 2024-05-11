// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: weirongguang <weirongguang@kylinos.cn>
//
// Based on tcpaccept.py - 2015 Brendan Gregg

#include "commons.h"
#include "tcpaccept.h"
#include "tcpaccept.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"
#include "map_helpers.h"
#include <arpa/inet.h>

static volatile sig_atomic_t exiting;

const char *argp_program_version = "tcpaccept 0.1";
const char *argp_program_bug_address = "Rongguang Wei <weirongguang@kylinos.cn>";
const char argp_program_doc[] =
"\nTrace TCP accepts\n"
"\n"
"EXAMPLES:\n"
"    tcpaccept             # trace all TCP accepts\n"
"    tcpaccept -t          # include timestamps\n"
"    tcpaccept -p 181      # only trace PID 181\n"
"    tcpaccept -P 80,81    # only trace port 80 and 81\n"
"    tcpaccept -4          # trace IPv4 family only\n"
"    tcpaccept -6          # trace IPv6 family only\n"
;

static const struct argp_option opts[] = {
	{ "time", 'T', NULL, 0, "include time column on output (HH:MM:SS)", 0 },
	{ "timestamp", 't', NULL, 0, "include timestamp on output", 0 },
	{ "pid", 'p', "PID", 0, "trace this PID only", 0 },
	{ "port", 'P', "PORTS", 0, "comma-separated list of local ports to trace", 0 },
	{ "ipv4", '4', NULL, 0, "trace IPv4 family only", 0 },
	{ "ipv6", '6', NULL, 0, "trace IPv6 family only", 0 },
	{ "help", 'h', NULL, OPTION_HIDDEN, "Show this help message and exit", 0 },
	{}
};

static struct env {
	bool time;
	bool timestamp;
	bool pid;
	pid_t trace_pid;
	bool port;
	char *target_ports;
	bool ipv4_only;
	bool ipv6_only;
} env;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	char *port;

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
	case 'p':
		env.trace_pid = argp_parse_pid(key, arg, state);
		env.pid = true;
		break;
	case 'P':
		env.port = true;
		if (!arg) {
			warning("No ports specified\n");
			argp_usage(state);
		}
		env.target_ports = strdup(arg);
		port = strtok(arg, ",");
		while (port) {
			int port_num = strtol(port, NULL, 10);
			if (errno || port_num <= 0 || port_num > 65536) {
				warning("Invalid ports: %s\n", arg);
				argp_usage(state);
			}
			port = strtok(NULL, ",");
		}
		break;
	case '4':
		env.ipv4_only = true;
		break;
	case '6':
		env.ipv6_only = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static void print_header(void)
{
	if (env.time)
		printf("%-9s", "TIME");

	if (env.timestamp)
		printf("%-9s", "TIME(s)");

	printf("%-7s %-12s %-2s %-16s %-5s %-16s %-5s",
	       "PID", "COMM", "IP", "RADDR", "RPORT", "LADDR", "LPORT");
	printf("\n");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	char time_now[16];
	const struct data_t *event = data;
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;

	if (env.ipv4_only && event->af == AF_INET6)
		return 0;

	if (env.ipv6_only && event->af == AF_INET)
		return 0;

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

	if (env.time) {
		strftime_now(time_now, sizeof(time_now), "%H:%M:%S");
		printf("%-8s ", time_now);
	}

	if (env.timestamp)
		printf("%-8.3f ", time_since_start());

	printf("%-7d %-12.12s %-2d %-16s %-5d %-16s %-5d\n",
	       event->pid,
	       event->task,
	       event->af == AF_INET ? 4 : 6,
	       inet_ntop(event->af, &d, dst, sizeof(dst)),
	       ntohs(event->dport),
	       inet_ntop(event->af, &s, src, sizeof(src)),
	       event->lport);

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

	print_header();

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

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct tcpaccept_bpf *obj;
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
		warning("Failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return -1;
	}

	obj = tcpaccept_bpf__open_opts(&open_opts);
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

	if (env.pid)
		obj->rodata->trace_pid = env.trace_pid;

	obj->rodata->filter_by_port = env.port;

	err = tcpaccept_bpf__load(obj);
	if (err) {
		warning("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (env.port) {
		int port_map_fd = bpf_map__fd(obj->maps.ports);
		char *port = strtok(env.target_ports, ",");

		while (port) {
			int port_num = strtol(port, NULL, 10);

			bpf_map_update_elem(port_map_fd, &port_num,
					    &port_num, BPF_ANY);
			port = strtok(NULL, ",");
		}
	}

	err = tcpaccept_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing accept ... Hit Ctrl-C to end\n");

	err = print_events(buf);

cleanup:
	tcpaccept_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
