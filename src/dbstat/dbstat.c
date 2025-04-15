// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on dbstat.py - Sasha Goldshtein

#include "commons.h"
#include "dbstat.h"
#include "dbstat.skel.h"
#include "btf_helpers.h"
#include "uprobe_helpers.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;

const char *argp_program_version = "dbstat 0.1";
const char *argp_program_bug_address = "Yun Lu <luyun@kylinos.cn>";
const char argp_program_doc[] =
"\ndbstat: Display a histogram of MySQL and PostgreSQL query latencies.\n"
"\n"
"EXAMPLES:\n"
"    dbstat postgres     # display a histogram of PostgreSQL query latencies\n"
"    dbstat mysql -v     # display MySQL latencies and print the BPF program\n"
"    dbstat mysql -u     # display query latencies in microseconds (default: ms)\n"
"    dbstat mysql -m 5   # trace only queries slower than 5ms\n"
"    dbstat mysql -p 408 # trace queries in a specific process\n";

static char args_doc[] = "[interval [count]]";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "microseconds", 'u', NULL, 0, "display query latencies in microseconds (default: milliseconds)", 0 },
	{ "threshold", 'm', "NUM", 0, "trace queries slower than this threshold (ms)", 0 },
	{ "pid", 'p', "PID", 0, "the pid(s) to trace", 0 },
	{ "interval", 'i', "INT", 0, "print summary at this interval (seconds)", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static struct env {
	bool verbose;
	bool microseconds;
	int threshold;
	int pids[MAX_PID_TRACE_NUM];
	__u32 count;
	int interval;
	enum db_type db;
} env = {
	.interval = 99999999,
	.microseconds = false,
	.threshold = 0,
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
	case 'u':
		env.microseconds = true;
		break;
	case 'm':
		env.threshold = argp_parse_long(key, arg, state);
		break;
	case 'p':
		env.pids[env.count++] = argp_parse_pid(key, arg, state);
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
	case ARGP_KEY_ARG:
		switch (state->arg_num) {
		case 0:
			if (!strcmp(arg, "mysql"))
				env.db = DB_TYPE_MYSQL;
			else if (strcmp(arg, "postgres"))
				env.db = DB_TYPE_POSTGRESQL;
			else {
				warning("Invalid database: %s\n", arg);
				return ARGP_ERR_UNKNOWN;
			}
			break;
		default:
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int pidof_program(pid_t *pids, size_t pids_sz)
{
	FILE *fp;
	char cmd[100];
	char buf[1024];
	char *token;
	const char *prog = env.db == DB_TYPE_MYSQL ? "mysqld" : "postgres";
	int i = 0, err = -1;

	if (snprintf(cmd, sizeof(cmd), "pidof %s", prog) >= sizeof(cmd)) {
		warning("snprintf pidof prog failed\n");
		return -1;
	}
	fp = popen(cmd, "r");
	if (!fp) {
		warning("pidof %s failed\n", prog);
		return -1;
	}
	if (!fgets(buf, sizeof(buf), fp)) {
		warning("fgets pidof %s failed\n", prog);
		goto cleanup;
	}

	token = strtok(buf, " ");
	while (token) {
		if (i > pids_sz) {
			warning("too many pids\n");
			goto cleanup;
		}
		pids[i] = atoi(token);
		if (!pids[i]) {
			warning("atoi pid failed, pid: %s\n", token);
			goto cleanup;
		}
		token = strtok(NULL, " ");
		i++;
	}
	env.count = i;
	err = 0;

cleanup:
	pclose(fp);
	return err;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void print_and_reset_stats(struct dbstat_bpf *obj)
{
	char s[16], str[64];

	printf("%-8s \n", strftime_now(s, sizeof(s), "%H:%M:%S"));
	sprintf(str, "query latency (%s)", env.microseconds ? "us" : "ms");
	print_log2_hist(obj->bss->hists, MAX_SLOTS, str);
	printf("\n");
	memset(obj->bss->hists, 0, MAX_SLOTS * sizeof(__u32));
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int attach_language_usdt(struct dbstat_bpf *obj)
{
	int i, err = 0;
	char binary_path[PATH_MAX];
	const char *attach_type = env.db == DB_TYPE_MYSQL ? "mysql" : "postgresql";

	for (i = 0; i < env.count; i++) {
		err = resolve_binary_path("", env.pids[i], binary_path,
					  sizeof(binary_path));
		if (err < 0) {
			warning("get binary file path failed\n");
			return -1;
		}

		obj->links.trace_start = bpf_program__attach_usdt(obj->progs.trace_start,
								  env.pids[i], binary_path,
								  attach_type, "query__start",
								  NULL);
		if (!obj->links.trace_start) {
			err = errno;
			warning("attach usdt query__start failed: %s\n", strerror(errno));
			return err;
		}

		obj->links.trace_end = bpf_program__attach_usdt(obj->progs.trace_end,
								  env.pids[i], binary_path,
								  attach_type, "query__done",
								  NULL);
		if (!obj->links.trace_start) {
			err = errno;
			warning("attach usdt query__start failed: %s\n", strerror(errno));
			return err;
		}
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
		.args_doc = args_doc
	};
	struct dbstat_bpf *skel;
	int err;
	char pid_str[1024];
	int i, len = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.db == DB_TYPE_NONE) {
		warning("No database to trace.\n");
		return 1;
	}

	if (!env.count) {
		pidof_program(env.pids, ARRAY_SIZE(env.pids));
		if (!env.count) {
			warning("No pidof db to trace.\n");
			return 1;
		}
	}

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	skel = dbstat_bpf__open();
	if (!skel) {
		warning("Failed to open BPF objects\n");
		goto cleanup;
	}

	skel->rodata->microseconds = env.microseconds;
	skel->rodata->threshold = env.threshold;

	err = dbstat_bpf__load(skel);
	if (err) {
		warning("Failed to load BPF skelect: %d\n", err);
		goto cleanup;
	}

	if (!skel->bss) {
		warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = attach_language_usdt(skel);
	if (err) {
		warning("Failed to attch BPF USDT programs\n");
		goto cleanup;
	}

	err = dbstat_bpf__attach(skel);
	if (err) {
		warning("Failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	for (i = 0; i < env.count; i++) {
		len += sprintf(pid_str + len, "%d ", env.pids[i]);
	}
	pid_str[len-1] = '\0';

	printf("Tracing database queries for pids %s slower than %d ms...\n",
			pid_str, env.threshold);

	while (!exiting) {
		sleep(env.interval);
		print_and_reset_stats(skel);
	}

cleanup:
	dbstat_bpf__destroy(skel);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
