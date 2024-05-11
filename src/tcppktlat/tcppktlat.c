// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Wenbo Zhang
#include "commons.h"
#include "tcppktlat.h"
#include "tcppktlat.skel.h"
#include "compat.h"
#include "trace_helpers.h"

#include <arpa/inet.h>

static struct env {
	pid_t pid;
	pid_t tid;
	__u64 min_us;
	__u16 lport;
	__u16 rport;
	__u16 target_family;
	bool timestamp;
	bool verbose;
	int column_width;
} env = {
	.column_width = 15,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "tcppktlat 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace latency between TCP received pkt and picked up by userspace thread.\n"
"\n"
"USAGE: tcppkglat [--help] [-T] [-p PID] [-t TID] [-l LPORT] [-r RPORT] [-v]\n"
"                 [-W ADDR-WIDTH] [-4] [-6]\n"
"\n"
"EXAMPLES:\n"
"    tcppkglat             # Trace all TCP packet picked up latency\n"
"    tcppkglat -T          # summarize with timestamps\n"
"    tcppkglat -p          # filter for pid\n"
"    tcppkglat -t          # filter for tid\n"
"    tcppkglat -l          # filter for local port\n"
"    tcppkglat -r          # filter for remote port\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "tid", 't', "TID", 0, "Thread ID to trace", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "lport", 'l', "LPORT", 0, "Filter for local port", 0 },
	{ "rport", 'r', "RPORT", 0, "Filter for remote port", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "print-addr-width", 'W', "ADDR-WIDTH", 0, "Specify print width of tcp address (default 15)", 0 },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 skb only", 0 },
	{ "ipv6", '6', NULL, 0, "Trace IPv6 skb only", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
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
		env.tid = argp_parse_pid(key, arg, state);
		break;
	case 'l':
		env.lport = htons(argp_parse_long(key, arg, state));
		break;
	case 'r':
		env.rport = htons(argp_parse_long(key, arg, state));
		break;
	case 'W':
		env.column_width = argp_parse_long(key, arg, state);
		break;
	case '4':
		env.target_family = AF_INET;
		break;
	case '6':
		env.target_family = AF_INET6;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num != 0) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		env.min_us = argp_parse_long(key, arg, state);
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
	const struct event *e = data;
	char saddr[48], daddr[48];

	if (env.timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%-8s ", ts);
	}

	inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
	inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));

	printf("%-7d %-7d %-16s %-*s %-5d %-*s %-5d %-.2f\n",
	       e->pid, e->tid, e->comm, env.column_width, saddr, htons(e->sport),
	       env.column_width, daddr, htons(e->dport), e->delta_us / 1e3);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	struct tcppktlat_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = tcppktlat_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = env.pid;
	obj->rodata->target_tid = env.tid;
	obj->rodata->target_sport = env.lport;
	obj->rodata->target_dport = env.rport;
	obj->rodata->target_min_us = env.min_us;
	obj->rodata->target_family = env.target_family;

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		warning("Failed to create ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (probe_tp_btf("tcp_probe")) {
		bpf_program__set_autoload(obj->progs.tcp_probe_raw, false);
		bpf_program__set_autoload(obj->progs.tcp_rcv_space_adjust_raw, false);
		bpf_program__set_autoload(obj->progs.tcp_destroy_sock_raw, false);
	} else {
		bpf_program__set_autoload(obj->progs.tcp_probe_btf, false);
		bpf_program__set_autoload(obj->progs.tcp_rcv_space_adjust_btf, false);
		bpf_program__set_autoload(obj->progs.tcp_destroy_sock_btf, false);
	}

	err = tcppktlat_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcppktlat_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
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

	if (env.timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-7s %-7s %-16s %-*s %-5s %-*s %-5s %-s\n",
	       "PID", "TID", "COMM", env.column_width, "LADDR", "LPORT",
	       env.column_width, "RADDR", "RPORT", "MS");

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
	tcppktlat_bpf__destroy(obj);

	return err != 0;
}
