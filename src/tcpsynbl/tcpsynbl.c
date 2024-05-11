// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "tcpsynbl.h"
#include "tcpsynbl.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

static struct env {
	bool ipv4;
	bool ipv6;
	time_t interval;
	int times;
	bool timestamp;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "tcpsynbl 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize TCP SYN backlog as a histogram.\n"
"\n"
"USAGE: tcpsynbl [--help] [-T] [-4] [-6] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    tcpsynbl              # summarize TCP SYN backlog as a histogram\n"
"    tcpsynbl 1 10         # print 1 second summaries, 10 times\n"
"    tcpsynbl -T 1         # 1s summaries with timestamps\n"
"    tcpsynbl -4           # trace IPv4 family only\n"
"    tcpsynbl -6           # trace IPv6 family only\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 family only", 0 },
	{ "ipv6", '6', NULL, 0, "Trace IPv6 family only", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
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
	case '4':
		env.ipv4 = true;
		break;
	case '6':
		env.ipv6 = true;
		break;
	case ARGP_KEY_END:
		if (env.ipv4 && env.ipv6) {
			warning("Only one --ipvX option should be used\n");
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		switch (state->arg_num) {
		case 0:
			env.interval = argp_parse_long(key, arg, state);
			break;
		case 1:
			env.times = argp_parse_long(key, arg, state);
			break;
		default:
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
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

static void disable_all_progs(struct tcpsynbl_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.tcp_v4_sync_recv_kprobe, false);
	bpf_program__set_autoload(obj->progs.tcp_v6_sync_recv_kprobe, false);
	bpf_program__set_autoload(obj->progs.tcp_v4_sync_recv_fentry, false);
	bpf_program__set_autoload(obj->progs.tcp_v6_sync_recv_fentry, false);
}

static void set_autoload_progs(struct tcpsynbl_bpf *obj, int version)
{
	if (version == 4) {
		if (fentry_can_attach("tcp_v4_sync_recv_sock", NULL))
			bpf_program__set_autoload(obj->progs.tcp_v4_sync_recv_fentry, true);
		else
			bpf_program__set_autoload(obj->progs.tcp_v4_sync_recv_kprobe, true);
	}

	if (version == 6) {
		if (fentry_can_attach("tcp_v6_sync_recv_sock", NULL))
			bpf_program__set_autoload(obj->progs.tcp_v6_sync_recv_fentry, true);
		else
			bpf_program__set_autoload(obj->progs.tcp_v6_sync_recv_kprobe, true);
	}
}

static int print_log2_hists(int fd)
{
	__u64 lookup_key = -1, next_key;
	struct hist hist;
	int err;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err) {
			warning("Failed to lookup hist: %d\n", err);
			return -1;
		}
		printf("backlog_max = %lld\n", next_key);
		print_log2_hist(hist.slots, MAX_SLOTS, "backlog");
		lookup_key = next_key;
	}

	lookup_key = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err) {
			warning("Failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct tcpsynbl_bpf *obj;
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

	obj = tcpsynbl_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	disable_all_progs(obj);

	if (env.ipv4) {
		set_autoload_progs(obj, 4);
	} else if (env.ipv6) {
		set_autoload_progs(obj, 6);
	} else {
		set_autoload_progs(obj, 4);
		set_autoload_progs(obj, 6);
	}

	err = tcpsynbl_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing SYN backlog size. Ctrl-C to end.\n");

	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			char ts[32];

			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s\n", ts);
		}

		err = print_log2_hists(bpf_map__fd(obj->maps.hists));
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	tcpsynbl_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
