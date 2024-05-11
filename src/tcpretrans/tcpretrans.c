// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: weirongguang <weirongguang@kylinos.cn>
//
// Based on tcpretrans.py - Brendan Gregg and Matthias Tafelmeier

#include "commons.h"
#include "tcpretrans.h"
#include "tcpretrans.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"
#include "map_helpers.h"
#include <arpa/inet.h>

#define INET_ADDRPORTSTRLEN		INET_ADDRSTRLEN + 6
#define INET6_ADDRPORTSTRLEN		INET6_ADDRSTRLEN + 6

static volatile sig_atomic_t exiting;

const char *argp_program_version = "tcpretrans 0.1";
const char *argp_program_bug_address = "Rongguang Wei <weirongguang@kylinos.cn>";
const char argp_program_doc[] =
"\ntcpretrans: Trace TCP retransmits\n"
"\n"
"EXAMPLES:\n"
"    tcpretrans             # trace TCP retransmits\n"
"    tcpretrans -l          # include TLP attempts\n"
"    tcpretrans -4          # trace IPv4 family only\n"
"    tcpretrans -6          # trace IPv6 family only\n"
;

const char *tcp_state[] = {
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
};

const char *tcp_type[] = {
	[1] = "R",
	[2] = "L",
};

static const struct argp_option opts[] = {
	{ "lossprobe", 'l', NULL, 0, "include tail loss probe attempts", 0 },
	{ "count", 'c', NULL, 0, "count occurred retransmits per flow", 0 },
	{ "ipv4", '4', NULL, 0, "trace IPv4 family only", 0 },
	{ "ipv6", '6', NULL, 0, "trace IPv6 family only", 0 },
	{ "help", 'h', NULL, 0, "Show this help message and exit", 0 },
	{}
};

static struct env {
	bool args_count;
	bool lossprobe;
	bool count;
	bool ipv4_only;
	bool ipv6_only;
} env;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'l':
		env.lossprobe = true;
		break;
	case 'c':
		env.count = true;
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

static void print_count_header(void)
{
	printf("\n%-25s %-25s %-10s\n", "LADDR:LPORT", "RADDR:RPORT",
				      "RETRANSMITS");
}

static void print_count_ipv4(int map_fd)
{
	static struct ipv4_flow_key_t keys[MAX_ENTRIES];
	__u32 value_size = sizeof(__u64);
	__u32 key_size = sizeof(keys[0]);
	static struct ipv4_flow_key_t zero;
	static __u64 counts[MAX_ENTRIES];
	char s[INET_ADDRPORTSTRLEN];
	char d[INET_ADDRPORTSTRLEN];
	__u32 n = MAX_ENTRIES;
	struct in_addr src, dst;

	if (dump_hash(map_fd, keys, key_size, counts, value_size, &n, &zero)) {
		warning("Dump_hash: %s", strerror(errno));
		return;
	}

	for (int i = 0; i < n; i++) {
		src.s_addr = keys[i].saddr;
		dst.s_addr = keys[i].daddr;

		sprintf(s, "%s:%d", inet_ntop(AF_INET, &src, s, sizeof(s)),
				    keys[i].lport);
		sprintf(d, "%s:%d", inet_ntop(AF_INET, &dst, d, sizeof(d)),
				    ntohs(keys[i].dport));

		printf("%-20s <-> %-20s %10lld\n", s, d, counts[i]);
	}
}

static void print_count_ipv6(int map_fd)
{
	static struct ipv6_flow_key_t keys[MAX_ENTRIES];
	__u32 value_size = sizeof(__u64);
	__u32 key_size = sizeof(keys[0]);
	static struct ipv6_flow_key_t zero;
	static __u64 counts[MAX_ENTRIES];
	char s[INET6_ADDRPORTSTRLEN];
	char d[INET6_ADDRPORTSTRLEN];
	struct in6_addr src, dst;
	__u32 n = MAX_ENTRIES;

	if (dump_hash(map_fd, keys, key_size, counts, value_size, &n, &zero)) {
		warning("dump_hash: %s\n", strerror(errno));
		return;
	}

	for (int i = 0; i < n; i++) {
		memcpy(src.s6_addr, keys[i].saddr, sizeof(src.s6_addr));
		memcpy(dst.s6_addr, keys[i].daddr, sizeof(dst.s6_addr));

		sprintf(s, "%s:%d", inet_ntop(AF_INET6, &src, s, sizeof(s)),
				    keys[i].lport);
		sprintf(d, "%s:%d", inet_ntop(AF_INET6, &dst, d, sizeof(d)),
				    ntohs(keys[i].dport));

		printf("%-20s <-> %-20s %10lld\n", s, d, counts[i]);
	}
}

static void print_count(int map_fd_ipv4, int map_fd_ipv6)
{
	while (!exiting)
		pause();

	print_count_header();

	if (!env.ipv6_only)
		print_count_ipv4(map_fd_ipv4);
	if (!env.ipv4_only)
		print_count_ipv6(map_fd_ipv6);
}

static void print_event_header(void)
{
	printf("%-8s %-7s %-2s %-20s %1s> %-20s %-4s", "TIME", "PID", "IP",
						       "LADDR:LPORT", "T",
						       "RADDR:RPORT", "STATE");
	printf("\n");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	char time_now[16];
	const struct event *event = data;
	char src[INET6_ADDRPORTSTRLEN], dst[INET6_ADDRPORTSTRLEN];
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

	strftime_now(time_now, sizeof(time_now), "%H:%M:%S");
	sprintf(src, "%s:%d", inet_ntop(event->af, &s, src, sizeof(src)),
			      event->lport);
	sprintf(dst, "%s:%d", inet_ntop(event->af, &d, dst, sizeof(dst)),
			      ntohs(event->dport));

	printf("%-8s %-7d %-2d %-20s %1s> %-20s %-4s ",
	       time_now,
	       event->pid,
	       event->af == AF_INET ? 4 : 6,
	       src,
	       tcp_type[event->type],
	       dst,
	       tcp_state[event->state]);

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

	print_event_header();

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
	struct tcpretrans_bpf *obj;
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

	obj = tcpretrans_bpf__open_opts(&open_opts);
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

	if (!env.lossprobe)
		bpf_program__set_autoload(obj->progs.tcp_send_loss_probe_kprobe,
					  false);

	if (tracepoint_exists("tcp", "tcp_retransmit_skb"))
		bpf_program__set_autoload(obj->progs.tcp_retransmit_skb_kprobe,
					  false);
	else
		bpf_program__set_autoload(obj->progs.tcp_retransmit_skb_entry,
					  false);

	err = tcpretrans_bpf__load(obj);
	if (err) {
		warning("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcpretrans_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing retransmits ... Hit Ctrl-C to end\n");

	if (env.count)
		print_count(bpf_map__fd(obj->maps.ipv4_count),
			    bpf_map__fd(obj->maps.ipv6_count));
	else
		err = print_events(buf);

cleanup:
	tcpretrans_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
