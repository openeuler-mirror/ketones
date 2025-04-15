// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "slabratetop.h"
#include "slabratetop.skel.h"
#include "trace_helpers.h"

#include <sys/param.h>

#define OUTPUT_ROWS_LIMIT	10240

enum SORT_BY {
	SORT_BY_CACHE_NAME,
	SORT_BY_CACHE_COUNT,
	SORT_BY_CACHE_SIZE,
};

static volatile sig_atomic_t exiting;

static pid_t target_pid = 0;
static bool clear_screen = true;
static int output_rows = 20;
static int sort_by = SORT_BY_CACHE_SIZE;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "slabratetop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace slab kmem cache alloc by process.\n"
"\n"
"USAGE: slabratetop [-h] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    slabratetop            # slab rate top, refresh every 1s\n"
"    slabratetop -p 181     # only trace PID 181\n"
"    slabratetop -s count   # sort columns by count\n"
"    slabratetop -r 100     # print 100 rows\n"
"    slabratetop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen", 0 },
	{ "sort", 's', "SORT", 0, "Sort columns, default size [name, count, size]", 0 },
	{ "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'p':
		target_pid = argp_parse_pid(key, arg, state);
		break;
	case 'C':
		clear_screen = false;
		break;
	case 's':
		if (!strcmp(arg, "name")) {
			sort_by = SORT_BY_CACHE_NAME;
		} else if (!strcmp(arg, "count")) {
			sort_by = SORT_BY_CACHE_COUNT;
		} else if (!strcmp(arg, "size")) {
			sort_by = SORT_BY_CACHE_SIZE;
		} else {
			warning("Invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		output_rows = MIN(OUTPUT_ROWS_LIMIT, argp_parse_long(key, arg, state));
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
			interval = argp_parse_long(key, arg, state);
		} else if (pos_args == 1) {
			count = argp_parse_long(key, arg, state);
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
	struct slabrate_info *s1 = (struct slabrate_info *)obj1;
	struct slabrate_info *s2 = (struct slabrate_info *)obj2;

	if (sort_by == SORT_BY_CACHE_NAME) {
		return strcasecmp(s1->name, s2->name);
	} else if (sort_by == SORT_BY_CACHE_COUNT) {
		return s2->count - s1->count;
	} else {
		return s2->size - s1->size;
	}
}

static int print_stat(struct slabratetop_bpf *obj)
{
	FILE *f;
	char *key, **prev_key = NULL;
	static struct slabrate_info values[OUTPUT_ROWS_LIMIT];
	int fd = bpf_map__fd(obj->maps.slab_entries);
	int err = 0, rows = 0;

	f = fopen("/proc/loadavg", "r");
	if (f) {
		char ts[32], buf[256];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		if (fread(buf, 1, sizeof(buf), f))
			printf("%8s loadavg: %s\n", ts, buf);
		fclose(f);
	}

	printf("%-32s %6s %10s\n", "CACHE", "ALLOCS", "BYTES");

	while (!bpf_map_get_next_key(fd, prev_key, &key)) {
		err = bpf_map_lookup_elem(fd, &key, &values[rows++]);
		if (err) {
			warning("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}

	qsort(values, rows, sizeof(struct slabrate_info), sort_column);
	rows = MIN(rows, output_rows);

	for (int i = 0; i < rows; i++)
		printf("%-32s %6lld %10lld\n",
		       values[i].name, values[i].count, values[i].size);

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
	struct slabratetop_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = slabratetop_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;

	err = slabratetop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = slabratetop_bpf__attach(obj);
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
		sleep(interval);

		if (clear_screen) {
			err = system("clear");
			if (err)
				break;
		}

		err = print_stat(obj);
		if (err)
			break;

		if (exiting || --count == 0)
			break;
	}

cleanup:
	slabratetop_bpf__destroy(obj);

	return err != 0;
}
