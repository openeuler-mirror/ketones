// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "tcprtt.h"
#include "tcprtt.skel.h"
#include "trace_helpers.h"
#include <arpa/inet.h>

static struct env {
	__u16 lport;
	__u16 rport;
	__u32 laddr;
	__u32 raddr;
	__u8 laddr_v6[IPV6_LEN];
	__u8 raddr_v6[IPV6_LEN];
	bool milliseconds;
	time_t duration;
	time_t interval;
	bool timestamp;
	bool laddr_hist;
	bool raddr_hist;
	bool extended;
	bool verbose;
} env = {
	.interval = 99999999,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "tcprtt 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize TCP RTT as a histogram.\n"
"\n"
"USAGE: \n"
"\n"
"EXAMPLES:\n"
"    tcprtt            # summarize TCP RTT\n"
"    tcprtt -i 1 -d 10 # print 1 second summaries, 10 times\n"
"    tcprtt -m -T      # summarize in millisecond, and timestamps\n"
"    tcprtt -p         # filter for local port\n"
"    tcprtt -P         # filter for remote port\n"
"    tcprtt -a         # filter for local address\n"
"    tcprtt -A         # filter for remote address\n"
"    tcprtt -b         # show sockets histogram by local address\n"
"    tcprtt -B         # show sockets histogram by remote address\n"
"    tcprtt -e         # show extension summary(average)\n";

static const struct argp_option opts[] = {
	{ "interval", 'i', "INTERVAL", 0, "summary interval, seconds" },
	{ "duration", 'd', "DURATION", 0, "total duration of trace, seconds" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "millisecond", 'm', NULL, 0, "millisecond histogram" },
	{ "lport", 'p', "LPORT", 0, "filter for local port" },
	{ "rport", 'P', "RPORT", 0, "filter for remote port" },
	{ "laddr", 'a', "LADDR", 0, "filter for local address" },
	{ "raddr", 'A', "RADDR", 0, "filter for remote address" },
	{ "byladdr", 'b', NULL, 0,
	  "show sockets histogram by local address" },
	{ "byraddr", 'B', NULL, 0,
	  "show sockets histogram by remote address" },
	{ "extension", 'e', NULL, 0, "show extension summary(average)" },
	{ "verbose", 'v', NULL, 0, "verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct in6_addr addr_v6;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case 'd':
		env.duration = argp_parse_long(key, arg, state);
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'p':
		env.lport = htons(argp_parse_long(key, arg, state));
		break;
	case 'P':
		env.rport = htons(argp_parse_long(key, arg, state));
		break;
	case 'a':
		if (strchr(arg, ':')) {
			if (inet_pton(AF_INET6, arg, &env.laddr_v6) < 1) {
				warning("Invalid local IPv6 address: %s\n", arg);
				argp_usage(state);
			}
		} else {
			if (inet_pton(AF_INET, arg, &env.laddr) < 0) {
				warning("Invalid local address: %s\n", arg);
				argp_usage(state);
			}
		}
		break;
	case 'A':
		if (strchr(arg, ':')) {
			if (inet_pton(AF_INET6, arg, &env.raddr_v6) < 1) {
				warning("Invalid remote address: %s\n", arg);
				argp_usage(state);
			}
		} else {
			if (inet_pton(AF_INET, arg, &env.raddr) < 0) {
				warning("Invalid remote address: %s\n", arg);
				argp_usage(state);
			}
		}
		break;
	case 'c':
		if (inet_pton(AF_INET6, arg, &addr_v6) < 1) {
			warning("invalid local IPv6 address: %s\n", arg);
			argp_usage(state);
		}
		memcpy(env.laddr_v6, &addr_v6, sizeof(env.laddr_v6));
		break;
	case 'C':
		if (inet_pton(AF_INET6, arg, &addr_v6) < 1) {
			warning("invalid remote IPv6 address: %s\n", arg);
			argp_usage(state);
		}
		memcpy(env.raddr_v6, &addr_v6, sizeof(env.raddr_v6));
		break;
	case 'b':
		env.laddr_hist = true;
		break;
	case 'B':
		env.raddr_hist = true;
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

static int print_map(struct bpf_map *map)
{
	const char *units = env.milliseconds ? "msecs" : "usecs";
	struct hist_key *lookup_key = NULL, next_key;
	int err, fd = bpf_map__fd(map);
	struct hist hist;

	while (!bpf_map_get_next_key(fd, lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			warning("Failed to lookup infos: %d\n", err);
			return -1;
		}

		if (env.laddr_hist)
			printf("Local Address = ");
		else if (env.raddr_hist)
			printf("Remote Address = ");
		else
			printf("All Address = ****** ");

		if (env.laddr_hist || env.raddr_hist) {
			__u16 family = next_key.family;
			char str[INET6_ADDRSTRLEN];

			if (!inet_ntop(family, next_key.addr, str, sizeof(str))) {
				perror("converting IP to string:");
				return -1;
			}

			printf("%s ", str);
		}

		if (env.extended)
			printf("[AVG %llu]", hist.latency / hist.cnt);
		printf("\n");
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		printf("\n");
		lookup_key = &next_key;
	}

	lookup_key = NULL;
	while (!bpf_map_get_next_key(fd, lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			warning("Failed to cleanup infos: %d\n", err);
			return -1;
		}
		lookup_key = &next_key;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	__u8 zero_addr_v6[IPV6_LEN] = {};
	struct tcprtt_bpf *obj;
	__u64 time_end = 0;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	if ((env.laddr || env.raddr)
	    && (memcmp(env.laddr_v6, zero_addr_v6, sizeof(env.laddr_v6)) || memcmp(env.raddr_v6, zero_addr_v6, sizeof(env.raddr_v6)))) {
		fprintf(stderr, "It is not permitted to filter by both IPv4 and IPv6\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = tcprtt_bpf__open();
	if (!obj) {
		warning("Failed to opne BPF object\n");
		return 1;
	}

	obj->rodata->target_laddr_hist = env.laddr_hist;
	obj->rodata->target_raddr_hist = env.raddr_hist;
	obj->rodata->target_show_ext = env.extended;
	obj->rodata->target_sport = env.lport;
	obj->rodata->target_dport = env.rport;
	obj->rodata->target_saddr = env.laddr;
	obj->rodata->target_daddr = env.raddr;
	memcpy(obj->rodata->target_saddr_v6, env.laddr_v6, sizeof(obj->rodata->target_saddr_v6));
	memcpy(obj->rodata->target_daddr_v6, env.raddr_v6, sizeof(obj->rodata->target_daddr_v6));
	obj->rodata->target_ms = env.milliseconds;

	if (fentry_can_attach("tcp_rcv_established", NULL))
		bpf_program__set_autoload(obj->progs.tcp_rcv_kprobe, false);
	else
		bpf_program__set_autoload(obj->progs.tcp_rcv, false);

	err = tcprtt_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcprtt_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		err = -errno;
		warning("Can't set signal handler: %s\n", strerror(err));
		goto cleanup;
	}

	printf("Tracing TCP RTT");
	if (env.duration)
		printf(" for %ld secs.\n", env.duration);
	else
		printf("... Hit Ctrl-C to end.\n");

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	/* main: poll */
	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			char ts[32];

			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s\n", ts);
		}

		err = print_map(obj->maps.hists);
		if (err)
			break;

		if (env.duration && get_ktime_ns() > time_end)
			goto cleanup;

		if (exiting)
			break;
	}

cleanup:
	tcprtt_bpf__destroy(obj);

	return err != 0;
}
