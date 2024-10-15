// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on compactsnoop.py - Wenbo Zhang

#include "commons.h"
#include "compactsnoop.h"
#include "compactsnoop.skel.h"
#include "compat.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

static struct ksyms *ksyms;
static __u64 *stacks;
static volatile sig_atomic_t exiting;
static __u64 initial_ts = 0;
// from include/linux/mmzone.h
static const char *zone_type_x86[] = {"ZONE_DMA", "ZONE_DMA32", "ZONE_NORMAL"};
static const char *zone_type_arm64[] = {"ZONE_DMA", "ZONE_DMA32", "ZONE_NORMAL", "ZONE_MOVABLE", "ZONE_DEVICE"};
static const char *zone_type_ppc64le[] = {"ZONE_NORMAL", "ZONE_MOVABLE"};
// from include/trace/evnets/mmflags.h and include/linux/compaction.h
static const char* compact_status[] = {"not_suitable_zone", "skipped", "deferred",
				       "no_suitable_page", "continue", "complete",
				       "partial_skipped", "contended", "success"};

enum machine_type {
	X86_64,
	PPC64LE,
	ARM64
};

static struct env {
	bool verbose;
	bool timestamp;
	bool extended_fields;
	bool kernel_stack;
	pid_t pid;
	enum machine_type machine_type;
} env;

const char *argp_program_version = "compactsnoop 0.1";
const char *argp_program_bug_address = "Yang Feng <yangfeng@kylinos.cn>";
const char argp_program_doc[] =
"compactsnoop: Trace compact zone\n"
"\n"
"USAGE: compactsnoop [-v] [-h] [-t] [-k] [-p PID] [-e]\n"
"\n"
"Example:\n"
"    compactsnoop                 # trace all compact stall\n"
"    compactsnoop -t              # include timestamps\n"
"    compactsnoop -k              # output kernel stack trace\n"
"    compactsnoop -p 181          # filter on a PID\n"
"    compactsnoop -e              # show extended fields\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "timestamp", 't', NULL, 0, "include timestamp on output", 0 },
	{ "extended-fields", 'e', NULL, 0, "show system memory state", 0 },
	{ "kernel-stack", 'k', NULL, 0, "output kernel stack trace", 0 },
	{ "pid", 'p', "PID", 0, "Trace process ID only", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 't':
		env.timestamp = true;
		break;
	case 'e':
		env.extended_fields = true;
		break;
	case 'k':
		env.kernel_stack = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
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
	struct data_t *event = data;
	int map_fd = *(int *)ctx;

	if (initial_ts == 0)
		initial_ts = event->ts;

	if (env.timestamp)
		printf("%-14.8f", (float)(event->ts - initial_ts) / 1000000);

	if (env.machine_type == X86_64)
		printf("%-14.14s %-8d %-4d %-12s %-5d ", event->comm, event->pid,
			event->nid, zone_type_x86[event->idx], event->order);
	else if (env.machine_type == PPC64LE)
		printf("%-14.14s %-8d %-4d %-12s %-5d ", event->comm, event->pid,
			event->nid, zone_type_ppc64le[event->idx], event->order);
	else if (env.machine_type == ARM64)
		printf("%-14.14s %-8d %-4d %-12s %-5d ", event->comm, event->pid,
			event->nid, zone_type_arm64[event->idx], event->order);

	if (event->sync)
		printf("%-7s", "SYNC");
	else
		printf("%-7s", "ASYNC");

	if (env.extended_fields)
		printf("%-8.3f %-8d %-8d %-8d %-8d", (float)(event->fragindex) / 1000,
			event->min, event->low, event->high, event->free);

	printf("%9.3f %16s\n", (float)(event->delta) / 1000000, compact_status[event->status]);

	if (env.kernel_stack) {
		bpf_map_lookup_elem(map_fd, &event->stack_id, stacks);
		for (size_t i = 0; i < PERF_MAX_STACK_DEPTH; i++) {
			if (!stacks[i])
				break;

			const struct ksym *ksym = ksyms__map_addr(ksyms, stacks[i]);
			if (ksym) {
				printf("\t%zu [<%016llx>] %s", i, stacks[i], ksym->name);
				printf("+0x%llx", stacks[i] - ksym->addr);
				if (ksym->module)
					printf(" [%s]", ksym->module);
				printf("\n");
			} else {
				printf("\t%zu [<%016llx>] <%s>\n", i, stacks[i], "null sym");
			}
		}
		printf("\n");
	}

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static int run_command(char *result, char *command, int len)
{
	FILE *fp;

	fp = popen(command, "r");
	if (fp == NULL) {
		perror("Failed to run command");
		return -1;
	}

	if (fgets(result, len, fp) == NULL) {
		perror("Failed to read output");
		return -1;
	}

	pclose(fp);
	return 0;
}

static int get_machine_type(void)
{
	char *command = "uname -m";
	char machine_type[16];

	if (run_command(machine_type, command, 16) < 0)
		return -1;

	if (strstr(machine_type, "x86_64") != NULL) {
		env.machine_type = X86_64;
		return 0;
	} else if (strstr(machine_type, "ppc64le") != NULL) {
		env.machine_type = PPC64LE;
		return 0;
	} else if (strstr(machine_type, "aarch64") != NULL) {
		env.machine_type = ARM64;
		return 0;
	} else
		return 1;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	DEFINE_SKEL_OBJECT(obj);
	struct bpf_buffer *buf = NULL;
	int err;
	int stack_fd;

	err = get_machine_type();
	if (err) {
		if (err == 1)
			printf("Currently only support x86_64, arm64 and power servers\n");
		return err;
	}

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = SKEL_OPEN_OPTS(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

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

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("Failed to load kallsyms\n");
		goto cleanup;
	}

	obj->rodata->target_tgid = env.pid;
	obj->rodata->extended_fields = env.extended_fields;

	if (!env.extended_fields) {
		bpf_program__set_autoload(obj->progs.kretprobe_fragmentation_index_return, false);
		bpf_program__set_autoload(obj->progs.fexit_fragmentation_index_return, false);
	} else {
		if (fentry_can_attach("fragmentation_index", NULL))
			bpf_program__set_autoload(obj->progs.kretprobe_fragmentation_index_return,
						  false);
		else
			bpf_program__set_autoload(obj->progs.fexit_fragmentation_index_return,
						  false);
	}

	err = SKEL_LOAD(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = SKEL_ATTACH(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	stack_fd = bpf_map__fd(obj->maps.stack_traces);
	err = bpf_buffer__open(buf, handle_event, handle_lost_events, &stack_fd);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (env.timestamp)
		printf("%-14s", "TIME(s)");
	printf("%-14s %-8s %-4s %-12s %-5s %-7s", "COMM", "PID", "NODE", "ZONE", "ORDER", "MODE");
	if (env.extended_fields)
		printf("%-8s %-8s %-8s %-8s %-8s", "FRAGIDX", "MIN", "LOW", "HIGH", "FREE");
	printf("%9s %16s\n", "LAT(ms)", "STATUS");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %s\n", strerror(-err));
			break;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	SKEL_DESTROY(obj);
	cleanup_core_btf(&open_opts);
	ksyms__free(ksyms);
	free(stacks);

	return err != 0;
}
