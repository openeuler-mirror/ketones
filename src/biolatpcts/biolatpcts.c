// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on biolatpcts.py - Tejun Heo <tj@kernel.org>

#include "commons.h"
#include "biolatpcts.h"
#include "biolatpcts.skel.h"
#include "compat.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sysmacros.h>

#define MSEC		1000
#define SEC		(1000 * 1000)
#define IO_TYPE_NUM	4

static volatile sig_atomic_t exiting;
static __u64 last_rwdf_100ms[REDF_ARRAY_LEN];
static __u64 last_rwdf_1ms[REDF_ARRAY_LEN];
static __u64 last_rwdf_10us[REDF_ARRAY_LEN];
static __u64 rwdf_100ms[REDF_ARRAY_LEN];
static __u64 rwdf_1ms[REDF_ARRAY_LEN];
static __u64 rwdf_10us[REDF_ARRAY_LEN];
static const char *io_type[] = {"read", "write", "discard", "flush"};
static float base_pcts[] = {1, 5, 10, 16, 25, 50, 75, 84, 90, 95, 99, 100};

static struct env {
	bool verbose;
	bool debug_info;
	bool json;
	int interval;
	int which;
	char *dev;
	float *pcts;
	char *pcts_str;
	int len;
} env = {
	.interval		= 3,
	.which			= ON_DEVICE,
	.len			= sizeof(base_pcts) / sizeof(float),
};

const char *argp_program_version = "biolatpcts 0.1";
const char *argp_program_bug_address = "Yang Feng <yangfeng@kylinos.cn>";
const char argp_program_doc[] =
"biolatpcts: Monitor IO latency distribution of a block device.\n"
"\n"
"USAGE: biolatpcts DEV [-v] [-h] [-w {0, 1, 2}] [-i INTERVAL] [-p PCT,...] [-j] [-d]\n"
"\n"
"Example:\n"
"    biolatpcts /dev/nvme0n1                                # Print 3(default) second summaries\n"
"    biolatpcts /dev/nvme0n1 -p 01,90.0,99.9,99.99,100.0    # Calculated by custom percentage\n"
"    biolatpcts /dev/nvme0n1 -j                             # Output in JSON format\n"
"    biolatpcts 8:0                                         # Using device number MAJOR:MINOR tracing\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "debug-info", 'd', NULL, 0, "debug-info output", 0 },
	{ "interval", 'i', "INTERVAL", 0, "output interval, in seconds", 0 },
	{ "which", 'w', "WHICH", 0, "Which latency to measure, 0-2 for {from-rq-alloc,after-rq-alloc,on-device} respectively (default: on-device)", 0 },
	{ "pcts", 'p', "PCTS", 0, "Percentiles to calculate (default: 1,5,10,16,25,50,75,84,90,95,99,100)", 0 },
	{ "json", 'j', NULL, 0, "Output in json", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		env.debug_info = true;
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case 'w':
		env.which = argp_parse_long(key, arg, state);
		if (env.which != FROM_RQ_ALLOC && env.which != AFTER_RQ_ALLOC &&
		    env.which != ON_DEVICE) {
			printf("%s\n", argp_program_doc);
			printf("error: argument -w/--which: invalid choice\n");
			return ARGP_KEY_ERROR;
		}
		break;
	case 'p':
		env.pcts_str = arg;
		break;
	case 'j':
		env.json = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num != 0) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		env.dev = arg;
		break;
	case ARGP_KEY_END:
		if (!env.dev) {
			printf("%s\n", argp_program_doc);
			printf("error: the following arguments are required: DEV\n");
			return ARGP_KEY_ERROR;
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

static void find_pct(float req, __u64 total, __u64 *slots, int *idx, int *counted)
{
	while (*idx > 0) {
		*idx -= 1;
		if (slots[*idx] > 0) {
			*counted += slots[*idx];
			if (env.debug_info)
				printf("idx=%d counted=%d pct=%.1f req=%f\n",
					*idx, *counted, (float)*counted / total, req);
			if (((float)*counted / (float)total) * 100.0 >= (100.0 - req))
				break;
		}
	}
}

static void calc_lat_pct(__u64 *pct, __u64 total, __u64 *lat_100ms,
			 __u64 *lat_1ms, __u64 *lat_10us)
{
	__u64 *slots;
	__u32 gran;
	int data_sel = 0;
	int idx = 100;
	int counted = 0;
	int last_counted;
	float req;

	if (total == 0)
		return;

	for (int pct_idx = env.len - 1; pct_idx >= 0; --pct_idx) {
		req = env.pcts[pct_idx];
		while (true) {
			last_counted = counted;
			switch (data_sel) {
			case 0:
				gran = 100 * MSEC;
				slots = lat_100ms;
				break;
			case 1:
				gran = MSEC;
				slots = lat_1ms;
				break;
			case 2:
				gran = 10;
				slots = lat_10us;
				break;
			default:
				break;
			}
			find_pct(req, total, slots, &idx, &counted);
			if (env.debug_info)
				printf("pct_idx=%d req=%f gran=%u idx=%d counted=%d total=%lld\n",
					pct_idx, req, gran, idx, counted, total);
			if (idx > 0 || data_sel == 2)
				break;
			counted = last_counted;
			data_sel += 1;
			idx = 100;
		}
		pct[pct_idx] = gran * idx + gran / 2;
	}
}

static void format_usec(int lat)
{
	if (lat > SEC)
		printf("%5.1fs", (double)lat / SEC);
	else if (lat > 10 * MSEC)
		printf("%5.0fms", (double)lat / MSEC);
	else if (lat > MSEC)
		printf("%5.1fms", (double)lat / MSEC);
	else if (lat > 0)
		printf("%5dus", lat);
	else
		printf("      -");
}

static int get_dev_number(__u32 *major, __u32 *minor)
{
	int fd;
	struct stat statbuf;

	fd = open(env.dev, O_RDONLY);
	if (fd == -1) {
		sscanf(env.dev, "%d:%d", major, minor);
		printf("Major number = %d, Minor number =  %d\n", *major, *minor);
	} else if (fstat(fd, &statbuf) == -1) {
		perror("fstat");
		close(fd);
		return -1;
	} else {
		*major = (long)major(statbuf.st_rdev);
		*minor = (long)minor(statbuf.st_rdev);
		printf("Device %s: Major number = %ld, Minor number = %ld\n",
			env.dev, (long)major(statbuf.st_rdev), (long)minor(statbuf.st_rdev));
		close(fd);
	}
	return 0;
}

static int calculate_all_cpu_value_sum(int index, __u64 *value, long num_cpus,
				       int fd, __u64 *rwdf, __u64 *last_rwdf)
{
	__u64 total_value = 0;

	if (bpf_map_lookup_elem(fd, &index, value)) {
		warning("Error looking up map element\n");
		return -1;
	}
	for (int inner_cpu = 0; inner_cpu < num_cpus; inner_cpu++)
		total_value += value[inner_cpu];

	rwdf[index] = max(total_value - last_rwdf[index], 0ULL);
	last_rwdf[index] = total_value;

	return 0;
}

static int get_pcts()
{
	char *arg_copy = strdup(env.pcts_str);
	char *token = strtok(arg_copy, ",");
	int i = 0;
	float *pcts;

	while (token != NULL) {
		i++;
		token = strtok(NULL, ",");
	}
	free(arg_copy);
	env.len = i;

	pcts = malloc(sizeof(float) * i);
	if (!pcts) {
		warning("Failed to alloc pcts memory\n");
		return -1;
	}

	token = strtok(env.pcts_str, ",");
	i = 0;
	while (token != NULL) {
		pcts[i++] = atof(token);
		token = strtok(NULL, ",");
	}
	env.pcts = pcts;
	return 0;
}

static int get_data(struct biolatpcts_bpf *obj, __u64 *rwdf_total)
{
	__u64 *value;
	long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	int fd;
	int err = 0;

	value = malloc(sizeof(__u64) * num_cpus);
	if (!value) {
		warning("Failed to alloc memory\n");
		return -1;
	}

	for (int i = 0; i < REDF_ARRAY_LEN; ++i) {
		fd = bpf_map__fd(obj->maps.rwdf_100ms);
		if (calculate_all_cpu_value_sum(i, value, num_cpus, fd,
						rwdf_100ms, last_rwdf_100ms)) {
			err = -1;
			goto release_value;
		}

		fd = bpf_map__fd(obj->maps.rwdf_1ms);
		if (calculate_all_cpu_value_sum(i, value, num_cpus, fd,
						rwdf_1ms, last_rwdf_1ms)) {
			err = -1;
			goto release_value;
		}

		fd = bpf_map__fd(obj->maps.rwdf_10us);
		if (calculate_all_cpu_value_sum(i, value, num_cpus, fd,
						rwdf_10us, last_rwdf_10us)) {
			err = -1;
			goto release_value;
		}
		rwdf_total[i / 100] += rwdf_100ms[i];
	}

release_value:
	free(value);
	return err;
}

static void calculate_and_print_data(__u64 **rwdf_lat, __u64 *rwdf_total)
{
	for (int i = 0; i < IO_TYPE_NUM; ++i)
		for (int j = 0; j < env.len; ++j)
			rwdf_lat[i][j] = 0;

	for (int i = 0; i < IO_TYPE_NUM; ++i) {
		int left = i * 100;
		int right = left + 100;

		calc_lat_pct(rwdf_lat[i], rwdf_total[i],
			     rwdf_100ms + left,
			     rwdf_1ms + left,
			     rwdf_10us + left);

		if (env.debug_info) {
			printf("%-7s 100ms ", io_type[i]);
			for (int j = left; j < right; ++j)
				printf("%lld, ", rwdf_100ms[j]);

			printf("\n%-7s 1ms ", io_type[i]);
			for (int j = left; j < right; ++j)
				printf("%lld, ", rwdf_1ms[j]);

			printf("\n%-7s 10us ", io_type[i]);
			for (int j = left; j < right; ++j)
				printf("%lld, ", rwdf_10us[j]);
			printf("\n");
		}
	}

	if (env.json) {
		printf("{");
		for (int iot = 0; iot < IO_TYPE_NUM; ++iot) {
			printf("\"%s\": {", io_type[iot]);
			for (int pi = 0; pi < env.len; ++pi) {
				printf("\"%.2f\": ",  env.pcts[pi]);
				if (pi == env.len - 1)
					printf("%f", (double)rwdf_lat[iot][pi] / SEC);
				else
					printf("%f, ", (double)rwdf_lat[iot][pi] / SEC);
			}
			if (iot == IO_TYPE_NUM - 1)
				printf("}");
			else
				printf("}, ");
		}
		printf("}\n");
	}
	else {
		printf("\n%-7s", env.dev);
		for (int pct = 0; pct < env.len; ++pct)
			printf("%7.2f", env.pcts[pct]);

		printf("\n");
		for (int iot = 0; iot < IO_TYPE_NUM; ++iot) {
			printf("%-7s", io_type[iot]);
			for (int pi = 0; pi < env.len; ++pi)
				format_usec(rwdf_lat[iot][pi]);
			printf("\n");
		}
	}
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct biolatpcts_bpf *obj = NULL;
	int err;
	__u32 major, minor;
	__u64 *rwdf_lat[IO_TYPE_NUM] = {NULL};

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

	obj = biolatpcts_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	if (!env.pcts_str)
		env.pcts = base_pcts;
	else
		if (get_pcts())
			goto cleanup;

	err = get_dev_number(&major, &minor);
	if (err) {
		warning("Failed to get_dev_number\n");
		goto cleanup;
	}

	if (probe_tp_btf("block_rq_complete"))
		bpf_program__set_autoload(obj->progs.block_rq_complete_raw, false);
	else
		bpf_program__set_autoload(obj->progs.block_rq_complete_btf, false);

	obj->rodata->major = major;
	obj->rodata->minor = minor;
	obj->rodata->which = env.which;

	err = biolatpcts_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = biolatpcts_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	for (int i = 0; i < IO_TYPE_NUM; ++i) {
		__u64 *pct = calloc(env.len, sizeof(__u64));

		if (!pct) {
			warning("Failed to alloc pct memory\n");
			goto cleanup;
		}
		rwdf_lat[i] = pct;
	}

	printf("Tracing IO latency distribution ... Hit Ctrl-C to end.\n");
	while (!exiting) {
		__u64 rwdf_total[IO_TYPE_NUM] = {0};

		sleep(env.interval);

		if (get_data(obj, rwdf_total))
			goto cleanup;

		calculate_and_print_data(rwdf_lat, rwdf_total);
	}

cleanup:
	biolatpcts_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	if (env.pcts_str)
		free(env.pcts);
	for (int i = 0; i < IO_TYPE_NUM; ++i)
		free(rwdf_lat[i]);
	return err != 0;
}
