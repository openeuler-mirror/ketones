// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "filetop.h"
#include "filetop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define OUTPUT_ROWS_LIMIT	10240

enum SORT {
	ALL,
	READS,
	WRITES,
	RBYTES,
	WBYTES,
};

static volatile sig_atomic_t exiting;
static volatile bool verbose = false;
static volatile int sort_by = ALL;

struct argument {
	pid_t target_pid;
	bool clear_screen;
	bool regular_file_only;
	int output_rows;
	int interval;
	int count;
};

const char *argp_program_version = "filetop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace file reads/writes by process.\n"
"\n"
"USAGE: filetop [-h] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    filetop            # file I/O top, refresh every 1s\n"
"    filetop -p 1216    # only trace PID 1216\n"
"    filetop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen" },
	{ "all", 'a', NULL, 0, "Include special files" },
	{ "sort", 's', "SORT", 0, "Sort columns, default all [all, reads, writes, rbytes, wbytes]" },
	{ "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct argument *argument = state->input;
	static int pos_args;
	int max_rows = OUTPUT_ROWS_LIMIT;

	switch (key) {
	case 'p':
		argument->target_pid = argp_parse_pid(key, arg, state);
		break;
	case 'C':
		argument->clear_screen = false;
		break;
	case 'a':
		argument->regular_file_only = false;
		break;
	case 's':
		if (!strcmp(arg, "all"))
			sort_by = ALL;
		else if (!strcmp(arg, "reads"))
			sort_by = READS;
		else if (!strcmp(arg, "writes"))
			sort_by = WRITES;
		else if (!strcmp(arg, "rbytes"))
			sort_by = RBYTES;
		else if (!strcmp(arg, "wbytes"))
			sort_by = WBYTES;
		else {
			warning("Invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		errno = 0;
		argument->output_rows = strtol(arg, NULL, 10);
		if (errno || argument->output_rows <= 0) {
			warning("Invalud rows: %s\n", arg);
			argp_usage(state);
		}
		argument->output_rows = min(max_rows, argument->output_rows);
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			argument->interval = strtol(arg, NULL, 10);
			if (errno || argument->interval <= 0) {
				warning("Invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			argument->count = strtol(arg, NULL, 10);
			if (errno || argument->count <= 0) {
				warning("Invalid count\n");
				argp_usage(state);
			}
		} else {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int sort_column(const void *obj1, const void *obj2)
{
	struct file_stat *s1 = (struct file_stat *)obj1;
	struct file_stat *s2 = (struct file_stat *)obj2;

	if (sort_by == READS) {
		return s2->reads - s1->reads;
	} else if (sort_by == WRITES) {
		return s2->writes - s1->writes;
	} else if (sort_by == RBYTES) {
		return s2->read_bytes - s1->read_bytes;
	} else if (sort_by == WBYTES) {
		return s2->write_bytes - s1->write_bytes;
	} else {
		return (s2->reads + s2->writes + s2->read_bytes + s2->write_bytes) -
			(s1->reads + s1->writes + s1->read_bytes + s1->write_bytes);
	}
}

static int print_stat(struct filetop_bpf *obj, struct argument *argument)
{
	FILE *f;
	int err = 0;
	struct file_id key, *prev_key = NULL;
	static struct file_stat values[OUTPUT_ROWS_LIMIT];
	int fd = bpf_map__fd(obj->maps.entries);
	int rows = 0;

	f = fopen("/proc/loadavg", "r");
	if (f) {
		char ts[32], buf[256] = {};

		strftime_now(ts, sizeof(ts), "%H:%M:%S");

		if (fread(buf, 1, sizeof(buf), f))
			printf("%8s loadavg: %s\n", ts, buf);
		fclose(f);
	}

	printf("%-7s %-16s %-6s %-6s %-7s %-7s %1s %s\n",
	       "TID", "COMM", "READS", "WRITES", "R_Kb", "W_Kb", "T", "FILE");

	while (!bpf_map_get_next_key(fd, prev_key, &key)) {
		err = bpf_map_lookup_elem(fd, &key, &values[rows++]);
		if (err) {
			warning("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}

	qsort(values, rows, sizeof(struct file_stat), sort_column);
	rows = min(rows, argument->output_rows);

	for (int i = 0; i < rows; i++) {
		printf("%-7d %-16s %-6lld %-6lld %-7lld %-7lld %c %s\n",
		       values[i].tid, values[i].comm, values[i].reads, values[i].writes,
		       values[i].read_bytes / 1024, values[i].write_bytes / 1024,
		       values[i].type, values[i].filename);
	}

	printf("\n");
	prev_key = NULL;

	while (!bpf_map_get_next_key(fd, prev_key, &key)) {
		err = bpf_map_delete_elem(fd, &key);
		if (err) {
			warning("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}

	return err;
}

int main(int argc, char *argv[])
{
	struct argument argument = {
		.clear_screen = true,
		.regular_file_only = true,
		.output_rows = 45,
		.interval = 1,
		.count = 99999999,
	};
	static struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct filetop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, &argument);
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

	obj = filetop_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF objects\n");
		return 1;
	}

	obj->rodata->target_pid = argument.target_pid;
	obj->rodata->regular_file_only = argument.regular_file_only;

	err = filetop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = filetop_bpf__attach(obj);
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
		sleep(argument.interval);

		if (argument.clear_screen){
			err = system("clear");
			if (err)
				goto cleanup;
		}

		err = print_stat(obj, &argument);
		if (err)
			goto cleanup;

		if (exiting || !--argument.count)
			break;
	}

cleanup:
	filetop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
