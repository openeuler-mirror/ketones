// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "drsnoop.h"
#include "drsnoop.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;
static volatile bool verbose = false;

struct argument {
	pid_t pid;
	pid_t tid;
	time_t duration;
	bool extended;
};

const char *argp_program_version = "drsnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace direct reclaim latency.\n"
"\n"
"USAGE: drsnoop [--help] [-p PID] [-t TID] [-d DURATION] [-e]\n"
"\n"
"EXAMPLES:\n"
"    drsnoop         # trace all direct reclaim events\n"
"    drsnoop -p 123  # trace pid 123\n"
"    drsnoop -t 123  # trace tid 123 (use for threads only)\n"
"    drsnoop -d 10   # trace for 10 seconds only\n"
"    drsnoop -e      # trace all direct reclaim events with extended faileds\n";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Total duration of trace in seconds" },
	{ "extended", 'e', NULL, 0, "Extended fields output" },
	{ "pid", 'p', "PID", 0, "Process PID to trace" },
	{ "tid", 't', "TID", 0, "Thread TID to trace" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static int pagesize;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct argument *argument = state->input;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		verbose = true;
		break;
	case 'd':
		errno = 0;
		argument->duration = strtol(arg, NULL, 10);
		if (errno || argument->duration <= 0) {
			warning("Invalid Duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'e':
		argument->extended = true;
		break;
	case 'p':
		argument->pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		errno = 0;
		argument->tid = strtol(arg, NULL, 10);
		if (errno || argument->tid <= 0) {
			warning("Invalid TID: %s\n", arg);
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

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	const struct argument *argument = ctx;
	char ts[32];

	strftime_now(ts, sizeof(ts), "%H:%M:%S");

	printf("%-8s %-16s %-6d %9.3f %7lld", ts, e->task, e->pid,
	       e->delta_ns / 1000000.0, e->nr_reclaimed);
	if (argument->extended)
		printf(" %9llu", e->nr_free_pages * pagesize / 1024);
	printf("\n");
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct argument argument = {};
	struct perf_buffer *pb = NULL;
	struct drsnoop_bpf *obj;
	__u64 time_end = 0;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, &argument);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = drsnoop_bpf__open();
	if (!obj) {
		warning("Faild to open BPF object\n");
		return 1;
	}

	obj->rodata->target_tgid = argument.pid;
	obj->rodata->target_pid = argument.tid;

	if (argument.extended) {
		struct ksyms *ksyms = ksyms__load();
		const struct ksym *ksym;

		if (!ksyms) {
			warning("Failed to load kallsyms\n");
			goto cleanup;
		}

		ksym = ksyms__get_symbol(ksyms, "vm_zone_stat");
		if (!ksym) {
			warning("Failed to get vm_zone_stat's addr\n");
			goto cleanup;
		}

		obj->rodata->vm_zone_stat_kaddr = ksym->addr;
		pagesize = sysconf(_SC_PAGESIZE);

		ksyms__free(ksyms);
	}

	if (probe_tp_btf("mm_vmscan_direct_reclaim_begin")) {
		bpf_program__set_autoload(obj->progs.direct_reclaim_begin_raw, false);
		bpf_program__set_autoload(obj->progs.direct_reclaim_end_raw, false);
	} else {
		bpf_program__set_autoload(obj->progs.direct_reclaim_begin_btf, false);
		bpf_program__set_autoload(obj->progs.direct_reclaim_end_btf, false);
	}

	err = drsnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = drsnoop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing direct reclaim events");
	if (argument.duration)
		printf(" for %ld secs.\n", argument.duration);
	else
		printf("... Hit Ctrl-C to end.\n");

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, &argument, NULL);
	if (!pb) {
		err = -errno;
		warning("Failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	/* setup duration */
	if (argument.duration)
		time_end = get_ktime_ns() + argument.duration * NSEC_PER_SEC;

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("%-8s %-16s %-6s %9s %7s", "TIME", "COMM", "PID", "DELTA(ms)", "RECLAIM");
	if (argument.extended)
		printf(" %9s", "FREEPAGES");
	printf("\n");

	/* main poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		if (argument.duration && get_ktime_ns() > time_end)
			goto cleanup;
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	drsnoop_bpf__destroy(obj);

	return err != 0;
}
