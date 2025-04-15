// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on tcpcong.py - Ping Gan

#include "commons.h"
#include "tcpcong.h"
#include "tcpcong.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include <arpa/inet.h>

#define INET6_ADDRPORTSTRLEN	INET6_ADDRSTRLEN + 6

static volatile sig_atomic_t exiting;
// this need to match with kernel state
static const char *state_name[] = {"open", "disorder", "cwr", "recovery", "loss"};
static const char *label[] = {"ms", "us"};

static struct env {
	bool verbose;
	bool timestamp;
	bool dist;
	int microseconds;
	int interval;
	int outputs;
	char *localport;
	char *remoteport;
} env = {
	.interval		= 99999999,
	.outputs		= 99999999,
};

const char *argp_program_version = "tcpcong 0.1";
const char *argp_program_bug_address = "Yang Feng <yangfeng@kylinos.cn>";
const char argp_program_doc[] =
"tcpcong: Summarize tcp socket congestion control status duration.\n"
"\n"
"USAGE: tcpcong [-v] [-h] [-l LOCALPORT] [-r REMOTEPORT] [-t] [-d] [-u] [-i INTERVAL] [-o OUTPUTS]\n"
"\n"
"Example:\n"
"    tcpcong                       # show tcp congestion status duration\n"
"    tcpcong -i 1 -o 10            # show 1 second summaries, 10 times\n"
"    tcpcong -l 3000-3006 -i 1     # 1s summaries, local port 3000-3006\n"
"    tcpcong -r 5000-5005 -i 1     # 1s summaries, remote port 5000-5005\n"
"    tcpcong -ut -i 1              # 1s summaries, microseconds, and timestamps\n"
"    tcpcong -d                    # show the duration as histograms\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "timestamp", 't', NULL, 0, "include timestamp on output", 0 },
	{ "interval", 'i', "INTERVAL", 0, "output interval, in seconds", 0 },
	{ "dist", 'd', NULL, 0, "show distributions as histograms", 0 },
	{ "microseconds", 'u', NULL, 0, "output in microseconds", 0 },
	{ "outputs", 'o', "OUTPUTS", 0, "number of outputs", 0 },
	{ "localport", 'l', "LOCALPORT", 0, "trace local ports only", 0 },
	{ "remoteport", 'r', "REMOTEPORT", 0, "trace the dest ports only", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'd':
		env.dist = true;
		break;
	case 'u':
		env.microseconds = 1;
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case 'o':
		env.outputs = argp_parse_long(key, arg, state);
		break;
	case 'l':
		env.localport = arg;
		break;
	case 'r':
		env.remoteport = arg;
		break;
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

static int print_data(struct tcpcong_bpf *obj, __u64 family)
{
	ip_flow_key_t lookup_key = { .lport = -1}, next_key;
	data_val_t stats;
	int fd;
	int err;
	char src[INET6_ADDRPORTSTRLEN], dst[INET6_ADDRPORTSTRLEN];

	if (family == AF_INET) {
		printf("%-32s %-32s %s%s %s%s %s%s %s%s %s%s %-5s\n",
			"LAddrPort", "RAddrPort", "Open_", label[env.microseconds], "Dod_",
			label[env.microseconds], "Rcov_", label[env.microseconds], "Cwr_",
			label[env.microseconds], "Los_", label[env.microseconds], "Chgs");
		fd = bpf_map__fd(obj->maps.ipv4_stat);
	} else {
		printf("%-32s %-32s %s%s %s%s %s%s %s%s %s%s %-5s\n",
			"LAddrPort6", "RAddrPort6", "Open_", label[env.microseconds], "Dod_",
			label[env.microseconds], "Rcov_", label[env.microseconds], "Cwr_",
			label[env.microseconds], "Los_", label[env.microseconds], "Chgs");
		fd = bpf_map__fd(obj->maps.ipv6_stat);
	}

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		lookup_key = next_key;
		err = bpf_map_lookup_elem(fd, &next_key, &stats);
		if (err < 0) {
			warning("Failed to lookup infos: %d\n", err);
			return err;
		}

		if (family == AF_INET) {
			sprintf(src, "%s/%d", inet_ntop(AF_INET, &next_key.saddr_v4,
							src, sizeof(src)), next_key.lport);
			sprintf(dst, "%s/%d", inet_ntop(AF_INET, &next_key.daddr_v4,
							dst, sizeof(dst)), next_key.dport);
		} else {
			sprintf(src, "%s/%d", inet_ntop(AF_INET6, next_key.saddr_v6,
							src, sizeof(src)), next_key.lport);
			sprintf(dst, "%s/%d", inet_ntop(AF_INET6, next_key.daddr_v6,
							dst, sizeof(dst)), next_key.dport);
		}
		if (stats.total_changes != 0) {
			if (env.microseconds)
				printf("%-32s %-32s %-7lld %-7lld %-7lld %-6lld %-6lld %-5lld\n",
					src, dst, stats.open_dura, stats.disorder_dura,
					stats.recover_dura, stats.cwr_dura, stats.loss_dura,
					stats.total_changes);
			else
				printf("%-32s %-32s %-7lld %-7lld %-7lld %-6lld %-6lld %-5lld\n",
					src, dst, stats.open_dura / 1000,
					stats.disorder_dura / 1000, stats.recover_dura / 1000,
					stats.cwr_dura / 1000, stats.loss_dura / 1000,
					stats.total_changes);
		}
	}

	return 0;
}

static int clear_map(int fd)
{
	ip_flow_key_t lookup_ip_key = { .lport = -1}, next_ip_key;
	int err;

	/* Clear the map */
	while (!bpf_map_get_next_key(fd, &lookup_ip_key, &next_ip_key)) {
		err = bpf_map_delete_elem(fd, &next_ip_key);
		if (err < 0) {
			warning("Failed to cleanup info: %d\n", err);
			return err;
		}
		lookup_ip_key = next_ip_key;
	}

	return 0;
}

static int print_log2_hists(struct tcpcong_bpf *obj)
{
	const char *units = env.microseconds ? "usecs" : "msecs";
	struct bpf_map *hists = obj->maps.hists;
	int err, fd = bpf_map__fd(hists);
	__u16 lookup_key = -1, next_key;
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		printf("tcp_congest_state = %s\n", state_name[next_key - 1]);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

static void get_port_range(__u16 *start_port, __u16 *end_port, char *port)
{
	sscanf(port, "%hu-%hu", start_port, end_port);
	printf("start_port: %d, end_port: %d\n", *start_port, *end_port);
	if (*start_port > *end_port)
		warning("Start greater than end, cancel filtering!\n");
}

static void disable_kprobe(struct tcpcong_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.tcp_fastretrans_alert_kprobe, false);
	bpf_program__set_autoload(obj->progs.tcp_fastretrans_alert_kretprobe, false);
	bpf_program__set_autoload(obj->progs.tcp_enter_cwr_kprobe, false);
	bpf_program__set_autoload(obj->progs.tcp_enter_cwr_kretprobe, false);
	bpf_program__set_autoload(obj->progs.tcp_process_tlp_ack_kprobe, false);
	bpf_program__set_autoload(obj->progs.tcp_process_tlp_ack_kretprobe, false);
	bpf_program__set_autoload(obj->progs.tcp_enter_loss_kprobe, false);
	bpf_program__set_autoload(obj->progs.tcp_enter_loss_kretprobe, false);
	bpf_program__set_autoload(obj->progs.tcp_enter_recovery_kprobe, false);
	bpf_program__set_autoload(obj->progs.tcp_enter_recovery_kretprobe, false);
}

static void disable_fentry(struct tcpcong_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.tcp_fastretrans_alert_fentry, false);
	bpf_program__set_autoload(obj->progs.tcp_fastretrans_alert_fexit, false);
	bpf_program__set_autoload(obj->progs.tcp_enter_cwr_fentry, false);
	bpf_program__set_autoload(obj->progs.tcp_enter_cwr_fexit, false);
	bpf_program__set_autoload(obj->progs.tcp_process_tlp_ack_fentry, false);
	bpf_program__set_autoload(obj->progs.tcp_process_tlp_ack_fexit, false);
	bpf_program__set_autoload(obj->progs.tcp_enter_loss_fentry, false);
	bpf_program__set_autoload(obj->progs.tcp_enter_loss_fexit, false);
	bpf_program__set_autoload(obj->progs.tcp_enter_recovery_fentry, false);
	bpf_program__set_autoload(obj->progs.tcp_enter_recovery_fexit, false);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	DEFINE_SKEL_OBJECT(obj);
	char time[16];
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		goto cleanup;

	if (!bpf_is_root())
		goto cleanup;

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		goto cleanup;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = SKEL_OPEN_OPTS(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	if (tracepoint_exists("tcp", "tcp_cong_state_set")) {
		disable_kprobe(obj);
		disable_fentry(obj);
	} else if (fentry_can_attach("tcp_fastretrans_alert", NULL)) {
		disable_kprobe(obj);
		bpf_program__set_autoload(obj->progs.handle_tcp_cong, false);
	} else {
		disable_fentry(obj);
		bpf_program__set_autoload(obj->progs.handle_tcp_cong, false);
	}

	obj->rodata->dist = env.dist;
	obj->rodata->microseconds = env.microseconds;
	if (env.localport)
		get_port_range(&obj->rodata->start_lport, &obj->rodata->end_lport, env.localport);
	if (env.remoteport)
		get_port_range(&obj->rodata->start_rport, &obj->rodata->end_rport, env.remoteport);

	err = SKEL_LOAD(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = SKEL_ATTACH(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing tcp congestion control status duration... Hit Ctrl-C to end.\n");
	while (!exiting && env.outputs) {
		sleep(env.interval);

		printf("\n");
		if (env.timestamp)
			printf("%-8s\n", strftime_now(time, sizeof(time), "%H:%M:%S"));

		if (env.dist) {
			print_log2_hists(obj);
		} else {
			if (print_data(obj, AF_INET))
				goto cleanup;
			if (print_data(obj, AF_INET6))
				goto cleanup;
		}
		if (clear_map(bpf_map__fd(obj->maps.ipv4_stat)))
			goto cleanup;
		if (clear_map(bpf_map__fd(obj->maps.ipv6_stat)))
			goto cleanup;

		env.outputs--;
	}

cleanup:
	SKEL_DESTROY(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
