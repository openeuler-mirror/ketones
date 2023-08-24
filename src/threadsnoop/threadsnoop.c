// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "threadsnoop.h"
#include "threadsnoop.skel.h"
#include "compat.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

static volatile sig_atomic_t exiting;
static bool verbose = false;

const char *argp_program_version = "threadsnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"List new thread creation.\n"
"\n"
"USAGE: threadsnoop [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char ts[16];
	struct syms_cache *syms_cache = *((struct syms_cache **)ctx);
	const struct syms *syms;
	const struct sym *sym = NULL;

	syms = syms_cache__get_syms(syms_cache, e->pid);
	if (syms)
		sym = syms__map_addr(syms, e->function_addr);

	strftime_now(ts, sizeof(ts), "%H:%M:%S");
	printf("%-10s %-7d %-16s ", ts, e->pid, e->comm);

	if (sym)
		printf("%s\n", demangling_cplusplus_function(sym->name));
	else
		printf("0x%llx [unknown]\n", e->function_addr);

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on cpu #%d\n", lost_cnt, cpu);
}

static int attach_uprobes(struct threadsnoop_bpf *obj, struct bpf_link **link)
{
	char *pthread_lib_path;
	off_t func_off;
	int err = 0;

	pthread_lib_path = find_library_so("/usr/bin/ls", "/libpthread.so");
	func_off = get_elf_func_offset(pthread_lib_path, "pthread_create");
	if (func_off < 0) {
		warning("Could not find pthread_create in %s\n", pthread_lib_path);
		err = 1;
		goto cleanup;
	}

	*link = bpf_program__attach_uprobe(obj->progs.pthread_create, false,
					   -1, pthread_lib_path, func_off);
	if (!*link) {
		warning("Failed to attach pthread_create: %d\n", -errno);
		err = 1;
		goto cleanup;
	}

cleanup:
	free(pthread_lib_path);
	return err != 0;
}

int main(int argc, char *argv[])
{
	struct syms_cache *syms_cache = NULL;
	struct threadsnoop_bpf *obj;
	struct bpf_buffer *buf = NULL;
	struct bpf_link *link = NULL;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		warning("Failed to to create syms cache\n");
		err = -ENOMEM;
		goto cleanup;
	}

	obj = threadsnoop_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		err = 1;
		goto cleanup;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer\n");
		err = 1;
		goto cleanup;
	}

	err = threadsnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = attach_uprobes(obj, &link);
	if (err) {
		warning("Failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, &syms_cache);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("%-10s %-7s %-16s %s\n", "TIME(ms)", "PID", "COMM", "FUNC");

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %d\n", err);
			goto cleanup;
		}
		/* reset err to 0 when exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	threadsnoop_bpf__destroy(obj);
	if (syms_cache)
		syms_cache__free(syms_cache);
	if (link)
		bpf_link__destroy(link);

	return err != 0;
}
