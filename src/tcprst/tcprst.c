// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Rongguang Wei <weirongguang@kylinos.cn>

#include "commons.h"
#include "tcprst.h"
#include "tcprst.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"
#include "map_helpers.h"
#include <arpa/inet.h>

#define INET_ADDRPORTSTRLEN	INET_ADDRSTRLEN + 6

static volatile sig_atomic_t exiting;

struct ksyms *ksyms;
static __u64 *stacks;

const char *argp_program_version = "tcprst 0.1";
const char *argp_program_bug_address = "Rongguang Wei <weirongguang@kylinos.cn>";
const char argp_program_doc[] =
"\ntcpretrans: Trace TCP rst by the kernel\n"
"\n"
"EXAMPLES:\n"
"    tcprst                # trace kernel TCP rst contains send and receive\n"
"    tcprst -r             # trace kernel TCP rst receive only\n"
"    tcprst -s             # trace kernel TCP rst send only\n"
;

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "help", 'h', NULL, 0, "Show this help message and exit" },
	{ "receive", 'r', NULL, 0, "Trace TCP rst receive only" },
	{ "send", 's', NULL, 0, "Trace TCP rst send only" },
	{}
};

const char *tcp_direct[] = {
	[0] = "RECEIVE",
	[1] = "SEND",
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
	bool send;
	bool receive;
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
	case 'r':
		env.receive = true;
		break;
	case 's':
		env.send = true;
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
	printf("%-8s %-7s %-20s %-20s %-15s %s\n",
	       "TIME", "PID", "LADDR:LPORT", "RADDR:RPORT", "STATE", "S/R");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	char time_now[16] = {0};
	const struct data_t *event = data;
	char src[INET_ADDRPORTSTRLEN], dst[INET_ADDRPORTSTRLEN];
	int map_fd = *(int *)ctx;

	strftime_now(time_now, sizeof(time_now), "%H:%M:%S");
	sprintf(src, "%s:%d", inet_ntop(AF_INET, &event->saddr_v4, src, sizeof(src)),
			      event->sport);
	sprintf(dst, "%s:%d", inet_ntop(AF_INET, &event->daddr_v4, dst, sizeof(dst)),
			      ntohs(event->dport));

	print_event_header();
	printf("%-8s %-7d %-20s %-20s %-15s %s\n",
	       time_now,
	       event->pid,
	       src,
	       dst,
	       event->state ? tcp_state[event->state] : "NO CONNECTION",
	       tcp_direct[event->direct]);

	bpf_map_lookup_elem(map_fd, &event->stack_id, stacks);
	for (size_t i = 0; i < PERF_MAX_STACK_DEPTH; i++) {
		if (!stacks[i])
			break;

		const struct ksym *ksym = ksyms__map_addr(ksyms, stacks[i]);
		if (ksym) {
			printf("\t%4zu [<%016llx>] %s", i, stacks[i], ksym->name);
			printf("+0x%llx", stacks[i] - ksym->addr);
			if (ksym->module)
				printf(" [%s]", ksym->module);
			printf("\n");
		} else {
			printf("\t%4zu [<%016llx>] <%s>\n", i, stacks[i], "null sym");
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
	struct tcprst_bpf *obj;
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

	obj = tcprst_bpf__open_opts(&open_opts);
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

	if (env.receive) {
		bpf_program__set_autoload(obj->progs.tcp_send_active_reset_kprobe,
					  false);
		bpf_program__set_autoload(obj->progs.tcp_v4_send_reset_kprobe,
					  false);
	} else if (env.send) {
		bpf_program__set_autoload(obj->progs.tcp_reset_kprobe, false);
	}

	err = tcprst_bpf__load(obj);
	if (err) {
		warning("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcprst_bpf__attach(obj);
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

	printf("Tracing tcp rst ... Hit Ctrl-C to end\n");

	err = print_events(buf, bpf_map__fd(obj->maps.stack));

cleanup:
	tcprst_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	ksyms__free(ksyms);
	free(stacks);

	return err != 0;
}
