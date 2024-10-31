// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yuan Chen <chenyuan@kylinos.cn>
//
// Based on dbslower.py - Sasha Goldshtein
#include "commons.h"
#include "compat.h"
#include "dbslower.h"
#include "dbslower.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

static volatile sig_atomic_t exiting;

static struct env {
	pid_t pids[MAX_PID_TRACE_NUM];
	__u32 count;
	bool verbose;
	__u64 threshold;
	char binary_path[BINARY_PATH_BUF_SIZE];
	enum db_type type;
	enum db_mode mode;
	off_t func_off;
} env = {
	.threshold = 1000000,
	.mode = DB_MODE_USDT,
	.type = DB_TYPE_NONE,
};

const char *argp_program_version = "dbslower 0.1";
const char *argp_program_bug_address = "Yuan Chen <chenyuan@kylinos.cn>";
const char argp_program_doc[] =
"Trace MySQL and PostgreSQL queries slower than a threshold.\n"
"\n"
"USAGE: dbslower [-v] [-p PID [PID ...]] [-b PATH_TO_BINARY] [-m THRESHOLD] {mysql,postgres}\n"
"\n"
"examples:\n"
"dbslower postgres                  # trace PostgreSQL queries slower than 1ms\n"
"dbslower postgres -p 188 322       # trace specific PostgreSQL processes\n"
"dbslower mysql -p 480 -m 30        # trace MySQL queries slower than 30ms\n"
"dbslower mysql -p 480 -v           # trace MySQL queries & print the BPF program\n"
"dbslower mysql -x $(which mysqld)  # trace MySQL queries with uprobes\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "verbose mode: print the BPF program (for debugging purposes)" },
	{ "db", 1, "DB", 0, "the database engine to use" },
	{ "pid", 'p', "PID", 0, "the pid(s) to trace" },
	{ "exe", 'x', "EXE", 0, "path to binary" },
	{ "threshold", 'm', "NUM", 0, "trace queries slower than this threshold (ms)" },
	{}
};

static enum db_type get_db_type(char *p)
{
	if (!p)
		return DB_TYPE_NONE;

	if (!strcmp(p, "mysql"))
		return DB_TYPE_MYSQL;
	else if (!strcmp(p, "postgres"))
		return DB_TYPE_POSTGRESQL;
	else
		return DB_TYPE_NONE;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		env.pids[env.count++] = argp_parse_pid(key, arg, state);
		break;
	case 'x':
		memcpy(env.binary_path, arg, sizeof(env.binary_path));
		break;
	case 'm':
		env.threshold = argp_parse_float(key, arg, state) * 1000000;
		break;
	case 1:
		if (env.type == DB_TYPE_NONE)
			env.type = get_db_type(arg);
		break;
	case ARGP_KEY_ARG:
		if (isdigit(arg[0])) {
			if (env.count >= MAX_PID_TRACE_NUM) {
				warning("Max num of trace pid: %d\n", MAX_PID_TRACE_NUM);
				return -1;
			}
			int pid = argp_parse_pid(key, arg, state);
			if (!pid)
				break;
			env.pids[env.count++] = pid;
			break;
		}

		if (env.type == DB_TYPE_NONE)
			env.type = get_db_type(arg);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int set_mode(void)
{
	char buf[256];

	if (env.count <= 0 && strlen(env.binary_path) > 0) {
		if (env.type != DB_TYPE_MYSQL) {
			warning("Sorry at the moment PostgreSQL supports only USDT\n");
			return -1;
		}

		env.func_off = get_regex_elf_func_offset(env.binary_path, "\\w+dispatch_command\\w+", true, buf);
		if (env.func_off < 0) {
			warning("Count not find readline in %s\n", env.binary_path);
			return -1;
		}

		if (strstr(buf, "COM_DATA"))
			env.mode = DB_MODE_MYSQL57;
		else
			env.mode = DB_MODE_MYSQL56;
	}

	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_size)
{
	struct data_t *ev = data;
	double delta;

	delta = time_since_start();
	printf("%-14.6f %-8d %12.3f %s\n", delta, ev->pid,
		(float)(ev->duration) / 1000000, ev->query);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on cpu #%d!\n", lost_cnt, cpu);
}

void print_header(void)
{
	char str[1024] = {};
	int off_pos = 0;

	if (env.mode == DB_MODE_MYSQL56 || env.mode == DB_MODE_MYSQL57) {
		printf("Tracing database queries for application %s slower than %f ms...\n",
			env.binary_path, (float)env.threshold / 1000000);
	} else {
		int i;
		for (i = 0; i < env.count; i++) {
			off_pos = strlen(str);
			snprintf(str + off_pos, sizeof(str) - off_pos, "%d,", env.pids[i]);
		}
		str[off_pos - 1] = '\0';
		printf("Tracing database queries for pids %s slower than %f ms...\n",
			str, (float)env.threshold / 1000000);
	}
	printf("%-14s %-8s %12s %s\n", "TIME(s)", "PID", "MS", "QUERY");
}

static int pidof_program(const char *prog, pid_t *pids, size_t pids_sz)
{
	FILE *fp;
	char cmd[100];
	char buf[1024];
	char *token;
	int i = 0, err = -1;

	if (snprintf(cmd, sizeof(cmd), "pidof %s", prog) >= sizeof(cmd)) {
		warning("snprintf pidof prog failed\n");
		return -1;
	}
	fp = popen(cmd, "r");
	if (!fp) {
		warning("pidof failed\n");
		return -1;
	}
	if (!fgets(buf, sizeof(buf), fp)) {
		warning("fgets pidof failed\n");
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

static int attach_progs(struct dbslower_bpf *obj)
{
	char *binary_path = env.binary_path;
	pid_t *pids = env.pids;
	const char *attach_type = env.type == DB_TYPE_MYSQL ? "mysql" : "postgresql";
	const char *process_name = env.type == DB_TYPE_MYSQL ? "mysqld" : "postgres";

	if (env.mode == DB_MODE_MYSQL56 || env.mode == DB_MODE_MYSQL57) {
		obj->links.query_start_uprobe = bpf_program__attach_uprobe(obj->progs.query_start_uprobe,
									   false, -1,
									   binary_path,
									   env.func_off);
		if (!obj->links.query_start_uprobe) {
			warning("attach query_start uprobe attach failed");
			return -1;
		}

		obj->links.query_end_uprobe = bpf_program__attach_uprobe(obj->progs.query_end_uprobe,
									 false, -1,
									 binary_path,
									 env.func_off);
		if (!obj->links.query_end_uprobe) {
			warning("attach query_end uprobe attach failed");
			return -1;
		}
	} else {
		if (!env.count)
			pidof_program(process_name, env.pids, ARRAY_SIZE(env.pids));

		int i;
		for (i = 0; i < env.count; i++) {
			if (resolve_binary_path("", pids[i], binary_path, sizeof(env.binary_path)))
				return 1;

			obj->links.query_start_usdt = bpf_program__attach_usdt(obj->progs.query_start_usdt,
									       pids[i],
									       binary_path,
									       attach_type,
									       "query__start",
									       NULL);
			if (!obj->links.query_start_usdt) {
				warning("attach query_start usdt attach failed");
				return -1;
			}

			obj->links.query_end_usdt = bpf_program__attach_usdt(obj->progs.query_end_usdt,
									     pids[i],
									     binary_path,
									     attach_type,
									     "query__done",
									     NULL);
			if (!obj->links.query_end_usdt) {
				warning("attach query_end usdt attach failed");
				return -1;
			}
		}
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

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	struct dbslower_bpf *obj = NULL;
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
		return 1;
	}

	if (set_mode()) {
		warning("Set mode failed\n");
		return -1;
	}

	obj = dbslower_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->threshold = env.threshold;
	obj->rodata->db_mode = env.mode;

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = 1;
		warning("Failed to create create/perf buffer");
		goto cleanup;
	}

	err = dbslower_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		goto cleanup;
	}

	err = attach_progs(obj);
	if (err) {
		warning("Failed to attch BPF USDT/uprobe programs\n");
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	print_header();
	while (!exiting) {
		err = bpf_buffer__poll(buf, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %d\n", err);
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	dbslower_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}