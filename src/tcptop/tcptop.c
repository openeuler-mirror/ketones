// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "tcptop.h"
#include "tcptop.skel.h"
#include "trace_helpers.h"

#include <arpa/inet.h>
#include <sys/param.h>

#define OUTPUT_ROWS_LIMIT	10240
#define IPV4			0
#define PORT_LENGTH		5

enum SORT {
	ALL,
	SENT,
	RECEIVED,
};

static volatile sig_atomic_t exiting;

static struct env {
	pid_t target_pid;
	char *cgroup_path;
	bool cgroup_filtering;
	bool clear_screen;
	bool no_summary;
	bool ipv4_only;
	bool ipv6_only;
	int output_rows;
	int sort_by;
	int interval;
	int count;
	bool verbose;
} env = {
	.target_pid = -1,
	.clear_screen = true,
	.output_rows = 20,
	.interval = 1,
	.count = 99999999,
};

const char *argp_program_version = "tcptop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace sending and received operation over IP.\n"
"\n"
"USAGE: tcptop [-h] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    tcptop            # TCP top, refresh every 1s\n"
"    tcptop -p 1216    # only trace PID 1216\n"
"    tcptop -c path    # only trace the given cgroup path\n"
"    tcptop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ "ipv4", '4', NULL, 0, "Trace IPv4 family only" },
	{ "ipv6", '6', NULL, 0, "Trace IPv6 family only" },
	{ "nosummary", 'S', NULL, 0, "Skip system summary line" },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen" },
	{ "sort", 's', "SORT", 0, "Sort columns, default all [all, sent, received]" },
	{ "rows", 'r', "ROW", 0, "Maximum rows to print, default 20" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

struct info_t {
	struct ip_key_t key;
	struct traffic_t value;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		env.target_pid = argp_parse_pid(key, arg, state);
		break;
	case 'c':
		env.cgroup_path = arg;
		env.cgroup_filtering = true;
		break;
	case 'C':
		env.clear_screen = false;
		break;
	case 'S':
		env.no_summary = true;
		break;
	case '4':
		env.ipv4_only = true;
		break;
	case '6':
		env.ipv6_only = true;
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
	case 'r':
		env.output_rows = MIN(argp_parse_long(key, arg, state), OUTPUT_ROWS_LIMIT);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_END:
		if (env.ipv4_only && env.ipv6_only) {
			warning("Only one --ipvX option should be used\n");
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

static int sort_column(const void *obj1, const void *obj2)
{
	struct info_t *i1 = (struct info_t *)obj1;
	struct info_t *i2 = (struct info_t *)obj2;

	if (i1->key.family != i2->key.family) {
		/*
		 * i1 - i2 because we want to sort by increasing order (first
		 * AF_INET then AF_INET6).
		 */
		return i1->key.family - i2->key.family;
	}

	if (env.sort_by == SENT)
		return i2->value.sent - i1->value.sent;
	else if (env.sort_by == RECEIVED)
		return i2->value.received - i1->value.received;
	else
		return (i2->value.sent + i2->value.received) - (i1->value.sent + i1->value.received);
}

static int print_stat(struct tcptop_bpf *obj)
{
	struct ip_key_t key, *prev_key = NULL;
	static struct info_t infos[OUTPUT_ROWS_LIMIT];
	int fd = bpf_map__fd(obj->maps.ip_map);
	bool ipv6_header_printed = false;
	int rows = 0;
	int err = 0;

	if (!env.no_summary) {
		FILE *f = fopen("/proc/loadavg", "r");

		if (f) {
			char ts[16], buf[256];

			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			if (fread(buf, 1, sizeof(buf), f))
				printf("%8s loadavg: %s\n", ts, buf);
			fclose(f);
		}
	}

	while (!bpf_map_get_next_key(fd, prev_key, &infos[rows].key)) {
		err = bpf_map_lookup_elem(fd, &infos[rows].key, &infos[rows].value);
		if (err) {
			warning("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &infos[rows].key;
		rows++;
	}

	printf("%-7s %-12s %-21s %-21s %6s %6s", "PID", "COMM", "LADDR", "RADDR",
	       "RX_KB", "TX_KB\n");

	qsort(infos, rows, sizeof(struct info_t), sort_column);
	rows = MIN(rows, env.output_rows);

	for (int i = 0; i < rows; i++) {
		/* Default width to fit IPv4 plus port. */
		int column_width = 21;
		struct ip_key_t *key = &infos[i].key;
		struct traffic_t *value = &infos[i].value;

		if (key->family == AF_INET6) {
			/* Width to fit IPv6 plus port. */
			column_width = 51;
			if (!ipv6_header_printed) {
				printf("\n%-7s %-12s %-51s %-51s %6s %6s",
				       "PID", "COMM", "LADDR6", "RADDR6",
				       "RX_KB", "TX_KB\n");
				ipv6_header_printed = true;
			}
		}

		char saddr[INET6_ADDRSTRLEN];
		char daddr[INET6_ADDRSTRLEN];

		inet_ntop(key->family, &key->saddr, saddr, INET6_ADDRSTRLEN);
		inet_ntop(key->family, &key->daddr, daddr, INET6_ADDRSTRLEN);

		/*
		 * A port is stored in u16, so highest value is 65535, which is
		 * 5 characters long.
		 * We need one character more for ':'.
		 */
		size_t size = INET6_ADDRSTRLEN + PORT_LENGTH + 1;
		char saddr_port[size], daddr_port[size];

		snprintf(saddr_port, size, "%s:%d", saddr, key->lport);
		snprintf(daddr_port, size, "%s:%d", daddr, key->dport);

		printf("%-7d %-12.12s %-*s %-*s %6ld %6ld\n",
		       key->pid, key->name, column_width, saddr_port,
		       column_width, daddr_port,
		       value->received / 1024, value->sent / 1024);
	}

	printf("\n");

	prev_key = NULL;
	while (!bpf_map_get_next_key(fd, prev_key, &key)) {
		err = bpf_map_delete_elem(fd, &key);
		if (err) {
			warning("bpf_map_delete_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}

	return err;
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct tcptop_bpf *obj;
	int cgfd = -1;
	int err;
	int family = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	if (env.ipv4_only)
		family = AF_INET;
	if (env.ipv6_only)
		family = AF_INET6;

	obj = tcptop_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = env.target_pid;
	obj->rodata->target_family = family;
	obj->rodata->filter_cg = env.cgroup_filtering;

	err = tcptop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (env.cgroup_filtering) {
		int zero = 0;
		int cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);

		cgfd = open(env.cgroup_path, O_RDONLY);
		if (cgfd < 0) {
			warning("Failed opening Cgroup path: %s\n", env.cgroup_path);
			goto cleanup;
		}

		if (bpf_map_update_elem(cg_map_fd, &zero, &cgfd, BPF_ANY)) {
			warning("Failed adding target cgroup to map\n");
			goto cleanup;
		}
	}

	err = tcptop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (1) {
		sleep(env.interval);

		if (env.clear_screen) {
			err = system("clear");
			if (err)
				goto cleanup;
		}

		err = print_stat(obj);
		if (err)
			goto cleanup;

		if (exiting || --env.count == 0)
			goto cleanup;
	}

cleanup:
	if (env.cgroup_filtering && cgfd != -1)
		close(cgfd);
	tcptop_bpf__destroy(obj);

	return err != 0;
}
