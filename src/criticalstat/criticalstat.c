// SPDX-License-Identifier: GPL-2.0
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on criticalstat.py - Joel Fernandes

#include "commons.h"
#include "criticalstat.h"
#include "criticalstat.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"
#include "map_helpers.h"

static volatile sig_atomic_t exiting;

struct ksyms *ksyms;
static __u64 *stacks;

const char *argp_program_version = "criticalstat 0.1";
const char *argp_program_bug_address = "Yun Lu <luyun@kylinos.cn>";
const char argp_program_doc[] =
"\ncriticalstat: Trace long critical sections (IRQs or preemption disabled)\n"
"\n"
"EXAMPLES:\n"
"    criticalstat	     # run with default options: irq off for more than 100 uS\n"
"    criticalstat -p	     # find sections with preemption disabled for more than 100 uS\n"
"    criticalstat -d 500     # find sections with IRQs disabled for more than 500 uS\n"
"    criticalstat -p -d 500  # find sections with preemption disabled for more than 500 uS\n"
;
const char config_doc[] =
"Required tracing events are not available.\n"
"Make sure the kernel is built with CONFIG_DEBUG_PREEMPT,\n"
"CONFIG_PREEMPT_TRACER and CONFIG_PREEMPTIRQ_EVENTS\n"
"(CONFIG_PREEMPTIRQ_TRACEPOINTS in kernel 4.19 and later) enabled.\n"
"Also please disable CONFIG_PROVE_LOCKING and CONFIG_LOCKDEP\n"
"on older kernels.\n"
;

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "help", 'h', NULL, 0, "Show this help message and exit" },
	{ "preempt", 'p', NULL, 0, "Find long sections where preemption was off(default is irq)" },
	{ "duration", 'd', "NUM", 0, "Duration in uS (microseconds) below which we filter" },
	{}
};

static struct env {
	bool verbose;
	bool preempt;
	int duration;
} env = {
	.preempt = false,
	.duration = 100,
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
	case 'p':
		env.preempt = true;
		break;
	case 'd':
		env.duration = argp_parse_long(key, arg, state);
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct data_t *event = data;
	int map_fd = *(int *)ctx;
	const struct ksym *ksym_text;
	const struct ksym *ksym_sec[4];

	ksym_text = ksyms__get_symbol(ksyms, "_stext");
	if (!ksym_text) {
		warning("Failed to get _stext kernel address\n");
		return 0;
	}

	for (int i = 0; i < 4; i++) {
		ksym_sec[i] = ksyms__map_addr(ksyms, ksym_text->addr + event->addrs[i]);
		if (!ksym_sec[i])
			goto skip;
	}

	printf("===================================\n");
	printf("TASK: %s (pid %5lld tid %5lld) Total Time: %-9.3fus\n\n",
		event->comm, (event->id >> 32), (event->id & 0xffffffff),
		((float)event->time) / 1000);
	printf("Section start: %s -> %s\n", ksym_sec[0]->name, ksym_sec[1]->name);
	printf("Section end:   %s -> %s\n", ksym_sec[2]->name, ksym_sec[3]->name);

skip:
	bpf_map_lookup_elem(map_fd, &event->stack_id, stacks);
	for (size_t i = 0; i < PERF_MAX_STACK_DEPTH; i++) {
		if (!stacks[i])
			break;

		const struct ksym *ksym = ksyms__map_addr(ksyms, stacks[i]);
		if (ksym) {
			printf("\t%4zu [<%016llx>] %s", i, stacks[i], ksym->name);
			printf("+0x%llx", stacks[i] - ksym->addr);
			if (ksym->module)
				printf(" [%s]", ksym->module);
			printf("\n");
		} else {
			printf("\t%4zu [<%016llx>] <%s>\n", i, stacks[i], "null sym");
		}
	}

	printf("===================================\n");
	printf("\n");

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static int print_events(struct bpf_buffer *buf, int map_fd)
{
	int err;

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, &map_fd);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		return err;
	}

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %s\n",
				strerror(-err));
			break;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

	return err;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct criticalstat_bpf *obj;
	struct bpf_buffer *buf = NULL;
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
		return -1;
	}

	obj = criticalstat_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF objects\n");
		err = 1;
		goto cleanup;
	}

	obj->rodata->duration = env.duration * 1000;

	/* alloc space for storing a stack trace */
	stacks = calloc(PERF_MAX_STACK_DEPTH, sizeof(*stacks));
	if (!stacks) {
		warning("Failed to allocate stack array\n");
		err = -ENOMEM;
		goto cleanup;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer\n");
		err = -errno;
		goto cleanup;
	}

	if (env.preempt) {
		if (!tracepoint_exists("preemptirq", "preempt_disable")) {
			warning("No preempt_disable tracepoint!\n%s\n", config_doc);
			err = 1;
			goto cleanup;
		}
		bpf_program__set_autoload(obj->progs.irq_disable_entry,
					  false);
		bpf_program__set_autoload(obj->progs.irq_enable_entry,
					  false);
	} else {
		if (!tracepoint_exists("preemptirq", "irq_disable")) {
			warning("No irq_disable tracepoint!\n%s\n", config_doc);
			err = 1;
			goto cleanup;
		}
		bpf_program__set_autoload(obj->progs.preempt_disable_entry,
					  false);
		bpf_program__set_autoload(obj->progs.preempt_enable_entry,
					  false);
	}

	err = criticalstat_bpf__load(obj);
	if (err) {
		warning("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = criticalstat_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("Failed to load ksyms\n");
		err = -ENOMEM;
		goto cleanup;
	}

	printf("Finding critical section with %s disabled for > %d us.\n",
			env.preempt ? "preempt" : "irq", env.duration);
	printf("Hit Ctrl-C to end.\n");

	err = print_events(buf, bpf_map__fd(obj->maps.stack));

cleanup:
	ksyms__free(ksyms);
	bpf_buffer__free(buf);
	free(stacks);
	criticalstat_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
