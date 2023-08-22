// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Shida Zhang <zhangshida@kylinos.cn>
//
// Base on cpuunclaimed.py - COPYRIGHT: Copyright (c) 2016, Netflix, Inc.

#include <linux/perf_event.h>
#include <sys/syscall.h>
#include "commons.h"
#include "cpuunclaimed.h"
#include "cpuunclaimed.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"

static struct env {
	bool csv;
	bool fullcsv;
	bool timestamp;
	float interval;
	int count;
	int frequency;
	int wakeup_hz;
	int trigger;
	int debug;
	__u64 last_ts;
} env = {
	.interval = -1,
	.count = 99999999,
	.frequency = 99,
	.wakeup_hz = 10,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "cpuunclaimed 0.1";
const char *argp_program_bug_address = "Shida Zhang <zhangshida@kylinos.cn>";
const char argp_program_doc[] =
"Sample CPU run queues and calculate unclaimed idle CPU.\n"
"\n"
"USAGE: ./cpuuclaimed [-h] [-j] [-J] [-T] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"	./cpuunclaimed		# sample and calculate unclaimed idle CPUs,\n"
"		      		# output every 1 second (default)\n"
"	./cpuunclaimed 5 10	# print 5 second summaries, 10 times\n"
"	./cpuunclaimed -T 1	# 1s summaries and timestamps\n"
"	./cpuunclaimed -j	# raw dump of all samples (verbose), CSV\n"
"\n"
"positional arguments:\n"
"  interval	output interval, in seconds\n"
"  count		number of outputs\n"
"\n"
"optional arguments:\n";

static const struct argp_option opts[] = {
	{ "csv", 'j', NULL, 0,
	  "print sameple summaries (verbose) as comma-separated values" },
	{ "fullcsv", 'J', NULL, 0,
	  "print sample summaries with extra fields: CPU sample offsets" },
	{ "timestamp", 'T', NULL, 0, "include timestamp on output" },
	{ "help", 'h', NULL, OPTION_HIDDEN, "show this help message and exit" },
	{},
};

/*
 * array implementation
 */
struct array {
	struct event *data;
	int size;
	int capacity;
};

static struct array *create_array(int initial_capacity)
{
	struct array *arr = (struct array *)calloc(1, sizeof(struct array));
	arr->data =
		(struct event *)calloc(initial_capacity, sizeof(struct event));
	arr->size = 0;
	arr->capacity = initial_capacity;
	return arr;
}

static void resize_array(struct array *arr, int new_capacity)
{
	arr->data =(struct event *)realloc(arr->data, new_capacity * sizeof(struct event));
	arr->capacity = new_capacity;
}

static void append(struct array *arr, struct event value)
{
	if (arr->size == arr->capacity) {
		resize_array(arr, arr->capacity * 2);
	}
	arr->data[arr->size] = value;
	arr->size++;
}

static void delete_first(struct array *arr)
{
	if (arr->size == 0) {
		return; // array is already empty
	}
	for (int i = 1; i < arr->size; ++i) {
		arr->data[i - 1] = arr->data[i];
	}
	arr->size--;

	// Resize the array if it's less than half full
	if (arr->size < arr->capacity / 2) {
		resize_array(arr, arr->capacity / 2);
	}
}

static void delete_all(struct array *arr)
{
	// Keep a minimum capacity for the array
	int min_capacity = 4; // Adjust as needed
	free(arr->data);
	arr->data = (struct event *)calloc(min_capacity, sizeof(struct event));
	arr->size = 0;
	arr->capacity = min_capacity;
}

static void free_array(struct array *arr)
{
	free(arr->data);
	free(arr);
}

static int get_size(struct array *arr)
{
	return arr->size;
}

/* array end */

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'j':
		env.csv = true;
		break;
	case 'J':
		env.fullcsv = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
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

static int nr_cpus;

static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				      struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 1,
		.sample_freq = freq,
		.config = PERF_COUNT_SW_TASK_CLOCK,
	};

	for (int i = 0; i < nr_cpus; i++) {
		int fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);

		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;

			warning("Failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}

		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			warning("Failed to attach perf event on cpu: #%d!\n",
				i);
			close(fd);
			return -1;
		}
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

/*
 * cpu running status info.
 */
static int g_running;
static int g_idle;
static int g_positive;

static void reset_status(void)
{
	g_running = 0;
	g_idle = 0;
	g_positive = 0;
}

/* an array of events from all ncpus in each turn. */
static struct array *frame_arr;
/* an array of events from all time. */
static struct array *event_arr;
static void update_status(void)
{
	int running = 0;
	int queued = 0;
	int idle = 0;
	for (int i = 0; i < frame_arr->size; ++i) {
		struct event e = frame_arr->data[i];
		__u64 len = e.len;

		/* calculate the running task number.*/
		if (len > 0)
			running += 1;

		/* calculate the waiting task number.*/
		if (len > 1)
			queued += len - 1;
	}

	/* calculate the idle cpu number during $env.trigger time.*/
	idle += nr_cpus - running;

	/*
	* calculate the number of threads that could have run as the
	* minimum of idle and queued
	*/
	if ((idle > 0) && (queued > 0))
		g_positive += min(idle, queued);

	g_running += running;
	g_idle += idle;
}

static void print_cpu_map(void)
{
	int *lens_p = (int *)calloc(nr_cpus, sizeof(int));
	__u64 *offs_p = (__u64 *)calloc(nr_cpus, sizeof(__u64));

	__u64 min_ts = frame_arr->data[0].ts;

	for (int i = 0; i < frame_arr->size; ++i) {
		struct event e = frame_arr->data[i];
		lens_p[e.cpu] = e.len;

		if (env.fullcsv)
			offs_p[e.cpu] = frame_arr->data[i].ts - min_ts;
	}

	if (min_ts > 0) {
		if (env.timestamp) {
			char ts[32];
			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s,", ts);
		}

		printf("%llu,", min_ts);
		for (int i = 0; i < nr_cpus - 1; ++i) {
			printf("%d,", lens_p[i]);
		}
		printf("%d", lens_p[nr_cpus - 1]);

		if (env.fullcsv) {
			printf(",");
			for (int i = 0; i < nr_cpus - 1; i++) {
				printf("%llu,", offs_p[i]);
			}
			printf("%llu", offs_p[nr_cpus - 1]);
		}
		printf("\n");
	}

	free(offs_p);
	free(lens_p);
}

static void update_or_print(void)
{
	if (frame_arr->size == 0)
		return;

	__u64 min_ts = frame_arr->data[0].ts;
	__u64 max_ts = frame_arr->data[frame_arr->size - 1].ts;

	if (env.csv)
		print_cpu_map();
	else
		update_status();

	if (max_ts - min_ts > env.trigger / 2) {
		printf("ERROR: CPU samples arrived at skewed offsets "
		       "(CPUs may have powered down when idle), "
		       "spanning %llu ns (expected < %d ns). Debug with -J, "
		       "and see the man page. As output may begin to be "
		       "unreliable, exiting.\n",
		       max_ts - min_ts, env.trigger / 2);
		exiting = 1;
	}
}

static void calculate_status(void)
{
	if (env.csv)
		return;

	float f_unclaimed = 0;
	float f_util = 0;
	unsigned int total = g_running + g_idle;

	if (total) {
		f_unclaimed = (float)g_positive / total;
		f_util = (float)g_running / total;
	}

	if (env.debug)
		printf("DEBUG: hit %d running %d idle %d total %d buffered %d\n",
		       g_positive, g_running, g_idle, total, get_size(frame_arr));

	printf("%%CPU %6.2f%%, unclaimed idle %0.2f%%\n", 100 * f_util,
	       100 * f_unclaimed);
}

static int event_compare(const void *a, const void *b)
{
	const struct event *x = (struct event *)a;
	const struct event *y = (struct event *)b;

	if (x->ts < y->ts)
		return -1;

	if (x->ts > y->ts)
		return 1;

	return 0;
}

/*
 * Store the elements of which the time stamp is in range, aka a frame.
 * return true, a complete frame.
 * return false, a partial frame.
 */
static bool transfer_to_frame(struct array *arr)
{
	struct event e;
	__u64 ts;
	__u64 cpu;
	__u64 len;
	__u64 first_ts;
	__u64 first_cpu;
	__u64 first_len;

	bool complete = false;
	int total_add = 0;
	int prev_size = frame_arr->size;

	for (int i = 0; i < arr->size; ++i) {
		e = arr->data[i];
		ts = e.ts;
		cpu = e.cpu;
		len = e.len;

		if (env.debug >= 2)
			printf("DEBUG: ts %llu cpu %llu len %llu delta %llu trig %d\n",
			       ts, cpu, len, ts - env.last_ts,
			       ts - env.last_ts > env.trigger);
		if (ts - env.last_ts > env.trigger) {
			env.last_ts = ts;
			complete = true;
			break;
		}

		append(frame_arr, e);
		total_add++;

	}

	for (int i = 0; i < total_add; ++i) {
		e = frame_arr->data[prev_size + i];
		ts = e.ts;
		cpu = e.cpu;
		len = e.len;

		e = arr->data[0];
		first_ts = e.ts;
		first_cpu = e.cpu;
		first_len = e.len;

		if ((ts != first_ts) || (cpu != first_cpu) ||
		    (len != first_len))
			printf("Warning! frame_arr should be consistent with event_arr.\n");

		delete_first(arr);
	}

	return complete;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	append(event_arr, *e);
	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.parser = parse_arg,
		.options = opts,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	struct bpf_link **links = NULL;
	struct cpuunclaimed_bpf *obj;
	int err, i;
	float interval = 0;
	float wakeup_s = 1.0 / env.wakeup_hz;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.fullcsv)
		env.csv = true;
	if (env.csv)
		interval = 0.2;
	if ((env.interval != -1) && (env.fullcsv || env.csv)) {
		printf("ERROR: cannot use interval with either "
		       "-j or -J. Exiting.\n");
		exiting = true;
	}
	if (env.interval == -1)
		env.interval = 1;
	interval = env.interval;
	env.trigger = (int)(0.8 * (1000000000 / env.frequency));

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		warning("Failed to get # of possible cpus: '%s'!\n",
			strerror(-nr_cpus));
		return 1;
	}
	links = calloc(nr_cpus, sizeof(*links));
	if (!links) {
		warning("Failed to alloc links\n");
		return 1;
	}

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return 1;
	}

	obj = cpuunclaimed_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF objects\n");
		goto cleanup;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		warning("Failed to create ring/perf buffer\n");
		goto cleanup;
	}

	err = cpuunclaimed_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = open_and_attach_perf_event(env.frequency,
					 obj->progs.do_perf_event,
					 links);
	if (err)
		goto cleanup;

	err = cpuunclaimed_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs\n");
		goto cleanup;
	}

	if (env.csv) {
		if (env.timestamp)
			printf("TIME,");
		printf("TIMESTAMP_ns,");
		for (int i = 0; i < nr_cpus - 1; i++) {
			printf("CPU%d,", i);
		}
		printf("CPU%d", nr_cpus - 1);
		if (env.fullcsv) {
			printf(",");
			for (int i = 0; i < nr_cpus - 1; i++) {
				printf("OFFSET_ns_CPU%d,", i);
			}
			printf("OFFSET_ns_CPU%d", nr_cpus - 1);
		}
		printf("\n");
	} else
		printf("Sampling run queues... Output every %.0f seconds. "
		       "Hit Ctrl-C to end.\n",
		       env.interval);

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	event_arr= create_array(64);
	frame_arr= create_array(64);
	float slept = 0;
	while (!exiting) {
		reset_status();

		usleep(wakeup_s * 1000 * 1000);
		slept += wakeup_s;
		if (slept < 0.999 * interval)
			continue;
		slept = 0;

		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling perf buffer: %s\n",
				strerror(-err));
			goto cleanup;
		}
		if (env.debug >= 2)
			printf("DEBUG: begin samples loop, count %d\n",
			       get_size(event_arr));

		qsort(event_arr->data, event_arr->size,
		      sizeof(struct event), event_compare);

		bool complete = false;
		while (1) {
			complete = transfer_to_frame(event_arr);
			if (complete) {
				/* Finish the calculation and release
				 * the resources.
				 */
				update_or_print();
				if (exiting)
					break;
				delete_all(frame_arr);
			}
			if (!complete)
				break;
		}
		if (exiting)
			break;
		calculate_status();

		if (--env.count == 0)
			goto cleanup;

		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	for (i = 0; i < nr_cpus; i++) {
		bpf_link__destroy(links[i]);
	}
	free(links);
	free_array(frame_arr);
	free_array(event_arr);
	bpf_buffer__free(buf);
	cpuunclaimed_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
