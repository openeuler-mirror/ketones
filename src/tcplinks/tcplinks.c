// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>

#include "commons.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "tcplinks.h"
#include "tcplinks.skel.h"
#include <arpa/inet.h>
#include <sys/param.h>

static volatile sig_atomic_t exiting;

enum SORT {
	ALL,
	SENT,
	RECEIVED,
};

static struct {
	bool verbose;
	bool interval;
	bool clear_screen;
	int count;
	int sort_by;
} env = {
	.clear_screen = true,
	.interval = 1,
	.count = 99999999,
};

const char *argp_program_version = "tcplinks 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Show the tcp link currently running on the system.\n"
"\n"
"USAGE: tcplink [-h] [-v] [-C] [--sort all/sent/received] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    tcplink         # tcp links, refresh every 1s\n"
"    tcplink 5       # refresh every 5s\n"
"    tcplink 1 10    # refresh every 1s, 10 times\n";

static struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen" },
	{ "sort", 's', "SORT", 0, "Sort columns, default all [all, sent, received]" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'C':
		env.clear_screen = false;
		break;
	case 's':
		if (!strcmp(arg, "all")) {
			env.sort_by = ALL;
		} else if (!strcmp(arg, "sent")) {
			env.sort_by = SENT;
		} else if (!strcmp(arg, "received")) {
			env.sort_by = RECEIVED;
		} else {
			warning("Invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0) {
			env.interval = argp_parse_long(key, arg, state);
		} else if (state->arg_num == 1) {
			env.count = argp_parse_long(key, arg, state);
		} else {
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

static char *port2protocol(__u16 port, char *buf)
{
	switch (port) {
	case 21:
		return strcpy(buf, "ftp");
	case 22:
		return strcpy(buf, "ssh");
	case 23:
		return strcpy(buf, "telnet");
	case 25:
		return strcpy(buf, "smtp");
	case 53:
		return strcpy(buf, "dns");
	case 67:
	case 68:
		return strcpy(buf, "dhcp");
	case 80:
		return strcpy(buf, "http");
	case 110:
		return strcpy(buf, "pop3");
	case 143:
		return strcpy(buf, "imap");
	case 161:
	case 162:
		return strcpy(buf, "snmp");
	case 443:
		return strcpy(buf, "https");
	case 587:
		return strcpy(buf, "smtp");
	case 993:
		return strcpy(buf, "imaps");
	}

	snprintf(buf, 6, "%d", port);
	return buf;
}

struct link_map {
	__u64 key;
	struct link link;
};

static int sort_column(const void *o1, const void *o2)
{
	struct link_map *l1 = (struct link_map *)o1;
	struct link_map *l2 = (struct link_map *)o2;

	int sent = (l2->link.sent - l2->link.prev_sent) -
			(l1->link.sent - l1->link.prev_sent);
	int received = (l2->link.received - l2->link.prev_received) -
			(l1->link.received - l1->link.prev_received);

	switch (env.sort_by) {
	case SENT:
		return sent;
	case RECEIVED:
		return received;
	case ALL:
	default:
		return sent + received;
	}
}

static int print_links(struct tcplinks_bpf *obj)
{
	int fd = bpf_map__fd(obj->maps.links);
	__u64 key = 0, next_key;
	struct link_map links[MAX_ENTRIES] = {};
	int err = 0, rows = 0;
	int max_pid_len = 0;

	while (!bpf_map_get_next_key(fd, &key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &links[rows].link);
		if (err) {
			warning("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		key = next_key;
		links[rows].key = key;

		char num[10];
		sprintf(num, "%d", links[rows].link.pid);
		max_pid_len = MAX(max_pid_len, strlen(num));
		rows++;
	}

	qsort(links, rows, sizeof(struct link_map), sort_column);

	/*
	 * A port is stored in u16, so highest value is 65535, which is
	 * 5 characters long.
	 * We need one character more for ':'.
	 */
	int size = INET6_ADDRSTRLEN + 6;

	printf("%*s %-25s %*s %*s %12s %12s\n", max_pid_len, "PID", "COMM", size,
	       "LocalAddress", size, "RemoteAddress", "TX_kb", "RX_kb");
	for (int i = 0; i < MIN(rows, 30); i++) {
		char saddr[INET6_ADDRSTRLEN];
		char daddr[INET6_ADDRSTRLEN];

		struct link *link = &links[i].link;
		inet_ntop(link->family, &link->saddr, saddr, INET6_ADDRSTRLEN);
		inet_ntop(link->family, &link->daddr, daddr, INET6_ADDRSTRLEN);

		char saddr_port[size], daddr_port[size];

		char sport[5], dport[5];
		snprintf(saddr_port, size, "%s:%s", saddr, port2protocol(link->sport, sport));
		snprintf(daddr_port, size, "%s:%s", daddr, port2protocol(link->dport, dport));

		char executable_name[MAX_NAME_LENGTH];
		if (get_process_executable_name(link->pid, executable_name) < 0)
			continue;
		printf("%*d %-25.25s %*s %*s %12.2f %12.2f\n", max_pid_len,
		       link->pid, basename(executable_name),
		       size, saddr_port, size, daddr_port,
		       (double)(link->sent - link->prev_sent) / 1024,
		       (double)(link->received - link->prev_received) / 1024);
	}

	/* reset link sent/received */
	for (int i = 0; i < rows; i++) {
		links[i].link.prev_sent = links[i].link.sent;
		links[i].link.prev_received = links[i].link.received;
		bpf_map_update_elem(fd, &links[i].key, &links[i].link, BPF_EXIST);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct tcplinks_bpf *obj;
	static struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
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

	obj = tcplinks_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	if (probe_tp_btf("inet_sock_set_state"))
		bpf_program__set_autoload(obj->progs.inet_sock_set_state_raw, false);
	else
		bpf_program__set_autoload(obj->progs.inet_sock_set_state, false);

	err = tcplinks_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		goto cleanup;
	}

	err = tcplinks_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Failed to set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (!exiting) {
		sleep(env.interval);

		if (env.clear_screen) {
			err = system("clear");
			if (err)
				goto cleanup;
		}

		err = print_links(obj);
		if (err)
			goto cleanup;

		if (--env.count == 0)
			goto cleanup;
	}

cleanup:
	tcplinks_bpf__destroy(obj);

	return err != 0;
}
