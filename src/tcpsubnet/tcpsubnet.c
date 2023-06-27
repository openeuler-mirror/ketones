// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Rongguang Wei <weirongguang@kylinos.cn>
//
// Based on tcpsubnet.py - 2017 Rodrigo Manyari

#include "commons.h"
#include "tcpsubnet.h"
#include "tcpsubnet.skel.h"
#include "compat.h"
#include <arpa/inet.h>

#define INET_ADDRMASKSTRLEN     INET_ADDRSTRLEN + 3

static volatile sig_atomic_t exiting;
static char default_subnets[] =
"127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,0.0.0.0/0";
static struct subnet subnets[MAX_NETS];

const char *argp_program_version = "tcpsubnet 0.1";
const char *argp_program_bug_address = "Rongguang Wei <weirongguang@kylinos.cn>";
const char argp_program_doc[] =
"\nSummarize TCP send and aggregate by subnet\n"
"\n"
"EXAMPLES:\n"
"    tcpsubnet               # Trace TCP sent to the default subnets:\n"
"                            # 127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,\n"
"                            # 192.168.0.0/16,0.0.0.0/0\n"
"    tcpsubnet -f K          # Trace TCP sent to the default subnets\n"
"                            # aggregated in KBytes.\n"
"    tcpsubnet 10.80.0.0/24  # Trace TCP sent to 10.80.0.0/24 only\n"
"                            # add more subnets separated by a ','"
;

static const struct argp_option opts[] = {
	{ "interval", 'i', "INTERVAL", 0, "output interval, in seconds (default 1)" },
	{ "format", 'f', "FORMAT", 0, "[bkmBKM] format to report: bits, Kbits, \
				       Mbits, bytes, KBytes, MBytes (default B)" },
	{ "help", 'h', NULL, OPTION_HIDDEN, "Show this help message and exit" },
	{}
};

static struct env {
	int interval;
	bool format;
	char *format_unit;
	bool trace;
	char trace_subnets[MAX_LENS];
} env = {
	.interval = 1,
	.format_unit = "B",
	.trace = false,
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case 'f':
		env.format_unit = arg;
		break;
	case ARGP_KEY_ARG:
		if (strlen(arg) > MAX_LENS) {
			warning("Too many subnets to add\n");
			argp_usage(state);
		}
		sprintf(env.trace_subnets, "%s", arg);
		env.trace = true;
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

static int bytes_format(int bytes, char *flag)
{
	switch (*flag) {
	case 'b':
		bytes *= 8;
		break;
	case 'k':
		bytes = (bytes * 8) / 1024;
		break;
	case 'm':
		bytes = (bytes * 8) / 1024 / 1024;
		break;
	case 'B':
		bytes = bytes;
		break;
	case 'K':
		bytes = bytes / 1024;
		break;
	case 'M':
		bytes = bytes / 1024 / 1024;
		break;
	}

	return bytes;
}

static unsigned int mask_to_int(int n)
{
	return n ? 0xFFFFFFFF << (32 - n): 0;
}

static void parse_subnet(char *sub, int index)
{
	char s[INET_ADDRMASKSTRLEN];
	char *addr, *mask;

	sprintf(s, "%s", sub);
	addr = strtok(s, "/");
	mask = strtok(NULL, "/");

	subnets[index].netinfo = sub;
	subnets[index].netaddr = htonl(inet_network(addr));
	subnets[index].netmask = htonl(mask_to_int(strtol(mask, NULL, 10)));
}

static int parse_subnets(char *sub)
{
	char *addr, *save;
	int index = 0;

	addr = strtok_r(sub, ",", &save);
	while (addr) {
		parse_subnet(addr, index);
		addr = strtok_r(NULL, ",", &save);
		index++;
	}

	return index;
}

static void print_subnet(int map_fd_ipv4)
{
	__u16 index_key;
	__u16 prev_key = -1;
	__u64 send_bytes;
	int err;

	while (!bpf_map_get_next_key(map_fd_ipv4, &prev_key, &index_key)) {
		err = bpf_map_lookup_elem(map_fd_ipv4, &index_key, &send_bytes);
		if (err < 0) {
			warning("bpf_map_lookup_elem failed: %s\n",
				strerror(errno));
			break;
		}

		printf("%-21s %6d\n",
		       subnets[index_key].netinfo,
		       bytes_format(send_bytes, env.format_unit));

		prev_key = index_key;

		err = bpf_map_delete_elem(map_fd_ipv4, &index_key);
		if (err < 0) {
			warning("bpf_map_delete_elem failed: %s\n",
				strerror(errno));
			break;
		}
	}
}

static void print_timer(void)
{
	char time_now[32];

	strftime_now(time_now, sizeof(time_now), "[%m/%d/%y %H:%M:%S]");
	printf("%s\n", time_now);
}

static void print_count(int map_fd_ipv4)
{
	while (!exiting) {
		sleep(env.interval);
		print_timer();
		print_subnet(map_fd_ipv4);
	}
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct tcpsubnet_bpf *obj;
	int subnet_len = 0;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = tcpsubnet_bpf__open();
	if (!obj) {
		warning("Failed to open BPF objects\n");
		return 1;
	}

	if (env.trace)
		subnet_len = parse_subnets(env.trace_subnets);
	else
		subnet_len = parse_subnets(default_subnets);

	for (int i = 0; i < subnet_len; i++)
		obj->rodata->subnets[i] = subnets[i];
	obj->rodata->subnet_len = subnet_len;

	err = tcpsubnet_bpf__load(obj);
	if (err) {
		warning("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcpsubnet_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing... Output every %d secs. Hit Ctrl-C to end\n", env.interval);

	print_count(bpf_map__fd(obj->maps.ipv4_send_bytes));

cleanup:
	tcpsubnet_bpf__destroy(obj);

	return err != 0;
}
