// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Rongguang Wei <weirongguang@kylinos.cn>
//
// Based on tcpdrop.py - 2018 Brendan Gregg

#include "commons.h"
#include "tcpdrop.h"
#include "tcpdrop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"
#include "map_helpers.h"
#include <arpa/inet.h>

#define INET6_ADDRPORTSTRLEN	INET6_ADDRSTRLEN + 6

static volatile sig_atomic_t exiting;

struct ksyms *ksyms;
static __u64 *stacks;

const char *argp_program_version = "tcpdrop 0.1";
const char *argp_program_bug_address = "Rongguang Wei <weirongguang@kylinos.cn>";
const char argp_program_doc[] =
"\ntcpretrans: Trace TCP drops by the kernel\n"
"\n"
"EXAMPLES:\n"
"    tcpdrop                # trace kernel TCP drops\n"
"    tcpdrop -4             # trace IPv4 family only\n"
"    tcpdrop -6             # trace IPv6 family only\n"
;

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "ipv4", '4', NULL, 0, "trace IPv4 family only", 0 },
	{ "ipv6", '6', NULL, 0, "trace IPv6 family only", 0 },
	{ "help", 'h', NULL, 0, "Show this help message and exit", 0 },
	{}
};

const char *tcphdr_flag[] = {
	[0] = "FIN",
	[1] = "SYN",
	[2] = "RST",
	[3] = "PSH",
	[4] = "ACK",
	[5] = "URG",
	[6] = "ECE",
	[7] = "CWR",
};

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

static struct env {
	bool verbose;
	bool ipv4_only;
	bool ipv6_only;
} env;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
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
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static void print_event_header(void)
{
	printf("%-8s %-7s %-2s %-20s > %-20s %s (%s)\n", "TIME", "PID", "IP",
	       "SADDR:SPORT",  "DADDR:DPORT", "STATE", "FLAGS");
}

static void flags2str(__u8 flags, char *data)
{
	for (int i = 0; i < ARRAY_SIZE(tcphdr_flag); i++) {
		if (flags & (1 << i)) {
			if (*data) {
				strcat(data, " | ");
				strcat(data, tcphdr_flag[i]);
			} else {
				strcpy(data, tcphdr_flag[i]);
			}
		}
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	char time_now[16] = {0};
	char tcp_flags[32] = {0};
	const struct data_t *event = data;
	char src[INET6_ADDRPORTSTRLEN], dst[INET6_ADDRPORTSTRLEN];
	int map_fd = *(int *)ctx;
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
	}

	strftime_now(time_now, sizeof(time_now), "%H:%M:%S");
	flags2str(event->tcpflags, tcp_flags);
	sprintf(src, "%s:%d", inet_ntop(event->af, &s, src, sizeof(src)),
			      event->sport);
	sprintf(dst, "%s:%d", inet_ntop(event->af, &d, dst, sizeof(dst)),
			      ntohs(event->dport));

	print_event_header();
	printf("%-8s %-7d %-2d %-20s > %-20s %s (%s)\n",
	       time_now,
	       event->pid,
	       event->af == AF_INET ? 4 : 6,
	       src,
	       dst,
	       tcp_state[event->state],
	       tcp_flags);

	bpf_map_lookup_elem(map_fd, &event->stack_id, stacks);
	for (size_t i = 0; i < PERF_MAX_STACK_DEPTH; i++) {
		if (!stacks[i])
			break;

		const struct ksym *ksym = ksyms__map_addr(ksyms, stacks[i]);
		if (ksym) {
			printf("\t%zu [<%016llx>] %s", i, stacks[i], ksym->name);
			printf("+0x%llx", stacks[i] - ksym->addr);
			if (ksym->module)
				printf(" [%s]", ksym->module);
			printf("\n");
		} else {
			printf("\t%zu [<%016llx>] <%s>\n", i, stacks[i], "null sym");
		}
	}

	printf("\n");

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static int print_events(struct bpf_buffer *buf, int map_fd)
{
	int err;

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, &map_fd);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		return err;
	}

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
	struct tcpdrop_bpf *obj;
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

	obj = tcpdrop_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF objects\n");
		err = 1;
		goto cleanup;
	}

	/* alloc space for storing a stack trace */
	stacks = calloc(PERF_MAX_STACK_DEPTH, sizeof(*stacks));
	if (!stacks) {
		warning("Failed to allocate stack array\n");
		err = -ENOMEM;
		goto cleanup;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer\n");
		err = -errno;
		goto cleanup;
	}

	/* tcp_drop has been inlined and after
	 * commit 8fbf195798b5("tcp: add drop reason support to tcp_ofo_queue()")
	 * the function was no longer needed.
	 *
	 * kfree_skb_reason is a compromise way for trace the skb drop.
	 * Because the function would also be trigger when skb freed by
	 * kfree_skb, not only tcp_drop_reason.
	 */
	if (kprobe_exists("tcp_drop"))
		bpf_program__set_autoload(obj->progs.kfree_skb_reason_kprobe, false);
	else
		bpf_program__set_autoload(obj->progs.tcp_drop_kprobe, false);

	err = tcpdrop_bpf__load(obj);
	if (err) {
		warning("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcpdrop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("Failed to load ksyms\n");
		err = -ENOMEM;
		goto cleanup;
	}

	printf("Tracing skb drop ... Hit Ctrl-C to end\n");

	err = print_events(buf, bpf_map__fd(obj->maps.stack));

cleanup:
	tcpdrop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	ksyms__free(ksyms);
	free(stacks);

	return err != 0;
}
