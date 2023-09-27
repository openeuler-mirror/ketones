// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Base on cachetop.py - COPYRIGHT: Copyright (c) 2016-present, Facebook, Inc.
#include "commons.h"
#include "cachetop.h"
#include "cachetop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include <sys/param.h>

#define OUTPUT_ROWS_LIMIT	1024

enum SORT {
	HITS,
	MISSES,
	DIRTIES,
	RHIT,
	WHIT,
};

struct argument {
	pid_t target_pid;
	time_t	interval;
	int	count;
	int	output_rows;
	bool	clear_screen;
} argument = {
	.target_pid = -1,
	.interval = 5,
	.output_rows = 128,
	.count = 99999999,
	.clear_screen = true,
};

static volatile sig_atomic_t exiting;
static volatile bool verbose = false;
static volatile int sort_by = HITS;

const char *argp_program_version = "cachetop 0.1";
const char *argp_program_bug_address = "Youling Tang <tangyouling@kylinos.cn>";
const char argp_program_doc[] =
"show Linux page cache hit/miss statistics including read and write hit % per\n"
"processes in a UI like top.\n"
"\n"
"USAGE: cachetop [-h] [interval] [count] [sort] [rows]\n"
"\n"
"EXAMPLES:\n"
"    cachetop             # run with default option of 5 seconds delay\n"
"    cachetop -p 1216     # only trace PID 1216\n"
"    cachetop 1           # print every second hit/miss stats\n"
"    cachetop 5 10        # print 5 second summaries, 10 times";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen" },
	{ "sort", 's', "SORT", 0, "Sort columns, default hits" },
	{ "rows", 'r', "ROWS", 0, "Maximum rows to print, default 128" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		verbose = true;
		break;
	case 'p':
		argument.target_pid = argp_parse_pid(key, arg, state);
		break;
	case 'C':
		argument.clear_screen = false;
		break;
	case 's':
		if (!strcmp(arg, "hits")) {
			sort_by = HITS;
		} else if (!strcmp(arg, "misses")) {
			sort_by = MISSES;
		} else if (!strcmp(arg, "dirties")) {
			sort_by = DIRTIES;
		} else if (!strcmp(arg, "rhit")) {
			sort_by = RHIT;
		} else if (!strcmp(arg, "whit")) {
			sort_by = WHIT;
		} else {
			warning("Invalid sort method: %s. Only support 'hits', 'missess', "
				"'dirties', 'rhit' and 'whit'.\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		argument.output_rows = MIN(argp_parse_long(key, arg, state), OUTPUT_ROWS_LIMIT);
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0) {
			argument.interval = argp_parse_long(key, arg, state);
		} else if (state->arg_num == 1) {
			argument.count = argp_parse_long(key, arg, state);
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
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static int get_meminfo(__u64 *buffers, __u64 *cached)
{
	FILE *f;
	char *buffer = NULL,* buf = NULL;
	char content[16] = "";
	size_t len = 0;

	f = fopen("/proc/meminfo", "r");
	if (!f)
		return -1;

	while (getline(&buffer, &len, f) != -1) {
		if ((buf = strstr(buffer, "Buffers")) != NULL) {
			buffer[strlen(buffer) - 1] = 0;
			sscanf(buffer, "%s%s", content, content);
			*buffers = atoll(content);
		}

		if ((buf = strstr(buffer, "Cached")) != NULL &&
		    (!strstr(buffer, "SwapCached"))) {
			buffer[strlen(buffer) - 1] = 0;
			sscanf(buffer, "%s%s", content, content);
			*cached = atoll(content);
		}
	}

	free(buffer);
	fclose(f);
	return 0;
}

struct data_t {
	struct key_t key;
	__u64 hits;
	__u64 misses;
	__u64 dirties;
	float rhit;
	float whit;
};

static int sort_column(const void *obj1, const void *obj2)
{
	struct data_t *s1 = (struct data_t *)obj1;
	struct data_t *s2 = (struct data_t *)obj2;

	switch (sort_by) {
	case HITS:
		return s2->hits - s1->hits;
	case MISSES:
		return s2->misses - s1->misses;
	case DIRTIES:
		return s2->dirties - s1->dirties;
	case RHIT:
		return s2->rhit - s1->rhit;
	case WHIT:
		return s2->whit - s1->whit;
	default:
		return 0;
	}
}

static void get_value(__u64 val, struct data_t *data, struct key_t *key)
{
	__s64 apcl = 0, mpa = 0, apd = 0, rtaccess = 0, wtaccess = 0;
	__u64 mbd = 0;

	switch (key->nf) {
	case NF_APCL:
		apcl = (val > 0 ? val : 0);
		break;
	case NF_MPA:
		mpa = (val > 0 ? val : 0);
		break;
	case NF_MBD:
		mbd = (val > 0 ? val : 0);
		break;
	case NF_APD:
		apd = (val > 0 ? val : 0);
		break;
	default:
		warning("Unknown NF type!\n");
		return;
	}

	memcpy(&data->key, key, sizeof(struct key_t));

	/* hits = total cache access include reads(mpa) and writes(mbd) */
	data->hits = mpa + mbd;
	/* misses = total of add to lru which we do when we write(mbd) */
	data->misses = apcl + apd;
	data->dirties = mbd;

	/* rtaccess is the read hit % during the sample period */
	if (mpa > 0)
		rtaccess = (float)mpa / (data->hits + data->misses);
	/* wtaccess is the write hit % during the sample period */
	if (apcl > 0)
		wtaccess = (float)apcl / (data->hits + data->misses);

	if (rtaccess)
		data->rhit = 100 * rtaccess;
	if (wtaccess)
		data->whit = 100 * wtaccess;
}

static int print_stat(struct cachetop_bpf *obj)
{
	int err = 0, rows = 0;
	__u64 val, buffers, cached;
	char ts[16];
	static struct data_t datas[OUTPUT_ROWS_LIMIT];
	struct key_t key, *prev_key = NULL;
	int fd = bpf_map__fd(obj->maps.counts);

	strftime_now(ts, sizeof(ts), "%H:%M:%S");

	err = get_meminfo(&buffers, &cached);
	if (err)
		warning("Failed to get meminfo: %d\n", err);

	printf("%8s Buffers MB: %.0lld / Cached MB: %.0lld\n", ts, buffers / 1024, cached / 1024);

	printf("%-7s %-7s %-16s %-8s %-8s %-8s %-10s %-10s\n", "PID", "UID", "CMD", "HITS",
		"MISSES", "DIRTIES", "READ_HIT%", "WRITE_HIT%");

	while (!bpf_map_get_next_key(fd, prev_key, &key)) {
		err = bpf_map_lookup_elem(fd, &key, &val);
		if (err) {
			warning("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}

		memset(&datas[rows], 0, sizeof(struct data_t));
		get_value(val, &datas[rows++], &key);

		prev_key = &key;
	}

	prev_key = NULL;

	qsort(datas, rows, sizeof(struct data_t), sort_column);
	rows = MIN(rows, argument.output_rows);

	for (int i = 0; i < rows; i++) {
		struct data_t *data = &datas[i];

		printf("%-7d %-7s %-16s %8lld %8lld %8lld %9.2f%% %9.2f%%\n", data->key.pid,
			get_uid_name(data->key.uid), data->key.comm, data->hits, data->misses,
			data->dirties, data->rhit, data->whit);
	}

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
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct cachetop_bpf *obj;
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

	obj = cachetop_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	/*
	 * Function account_page_dirtied() is changed to folio_account_dirtied() in 5.15,
	 * introduce tracepoint writeback_dirty_{page,folio}.
	 */
	if (tracepoint_exists("writeback", "writeback_dirty_folio")) {
		bpf_program__set_autoload(obj->progs.kprobe_account_page_dirtied, false);
		bpf_program__set_autoload(obj->progs.kprobe_folio_account_dirtied, false);
		bpf_program__set_autoload(obj->progs.tracepoint_writeback_dirty_page, false);
	} else if (tracepoint_exists("writeback", "writeback_dirty_page")) {
		bpf_program__set_autoload(obj->progs.kprobe_account_page_dirtied, false);
		bpf_program__set_autoload(obj->progs.kprobe_folio_account_dirtied, false);
		bpf_program__set_autoload(obj->progs.tracepoint_writeback_dirty_folio, false);
	} else if (kprobe_exists("folio_account_dirtied")) {
		bpf_program__set_autoload(obj->progs.kprobe_account_page_dirtied, false);
		bpf_program__set_autoload(obj->progs.tracepoint_writeback_dirty_folio, false);
		bpf_program__set_autoload(obj->progs.tracepoint_writeback_dirty_page, false);
	} else if (kprobe_exists("account_page_dirtied")) {
		bpf_program__set_autoload(obj->progs.kprobe_folio_account_dirtied, false);
		bpf_program__set_autoload(obj->progs.tracepoint_writeback_dirty_folio, false);
		bpf_program__set_autoload(obj->progs.tracepoint_writeback_dirty_page, false);
	}

	obj->rodata->target_pid = argument.target_pid;

	err = cachetop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF programs: %d\n", err);
		goto cleanup;
	}

	err = cachetop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	while (1) {
		sleep(argument.interval);

		if (argument.clear_screen){
			err = system("clear");
			if (err)
				goto cleanup;
		}

		err = print_stat(obj);
		if (err)
			goto cleanup;

		if (exiting || --argument.count == 0)
			break;
	}

cleanup:
	cachetop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
