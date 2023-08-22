// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "biostacks.h"
#include "biostacks.skel.h"
#include "trace_helpers.h"

static struct env {
	char *disk;
	int duration;
	bool milliseconds;
	bool verbose;
} env = {
	.duration = -1,
};

const char *argp_program_version = "biostacks 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Tracing block I/O with init stacks.\n"
"\n"
"USAGE: biostacks [--help] [-d DISK] [-m] [duration]\n"
"\n"
"EXAMPLES:\n"
"    biostacks              # trace block I/O with init stacks.\n"
"    biostacks 1            # trace for 1 seconds only\n"
"    biostacks -d sdc       # trace sdc only\n";

static const struct argp_option opts[] = {
	{ "disk", 'd', "DISK", 0, "Trace this disk only" },
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'd':
		env.disk = arg;
		if (strlen(arg) + 1 > DISK_NAME_LEN) {
			warning("Invalid disk name: too long\n");
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.duration = strtoll(arg, NULL, 10);
			if (errno || env.duration <= 0) {
				warning("Invalid delay (in us) : %s\n", arg);
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
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{}

static void print_map(struct ksyms *ksyms, struct partitions *partitions, int fd)
{
	const char *units = env.milliseconds ? "msecs" : "usecs";
	struct rqinfo lookup_key = {}, next_key;
	const struct partition *partition;
	const struct ksym *ksym;
	int num_stack, i, err;
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			warning("Failed to lookup hist: %d\n", err);
			return;
		}
		partition = partitions__get_by_dev(partitions, next_key.dev);
		printf("%-14.14s %-6d %-7s\n",
			next_key.comm, next_key.pid,
			partition ? partition->name : "Unknown");
		num_stack = next_key.kern_stack_size /
				sizeof(next_key.kern_stack[0]);
		for (i = 0; i < num_stack; i++) {
			ksym = ksyms__map_addr(ksyms, next_key.kern_stack[i]);
			printf("%s\n", ksym ? ksym->name : "Unknown");
		}
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		printf("\n");
		lookup_key = next_key;
	}

	return;
}

static bool has_block_io_tracepoints(void)
{
	return tracepoint_exists("block", "block_io_start") &&
		tracepoint_exists("block", "block_io_done");
}

static void disable_blk_io_tracepoints(struct biostacks_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.block_io_start, false);
	bpf_program__set_autoload(obj->progs.block_io_done, false);
}

static bool has_block_io_fentry(void)
{
	return fentry_can_attach("blk_account_io_start", NULL) ||
		fentry_can_attach("__blk_account_io_start", NULL);
}

static void disable_blk_account_io_fentry(struct biostacks_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.blk_account_io_start, false);
	bpf_program__set_autoload(obj->progs.blk_account_io_done, false);
}

static void disable_blk_io_kprobe(struct biostacks_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.kprobe_blk_account_io_start, false);
	bpf_program__set_autoload(obj->progs.kprobe_blk_account_io_done, false);
}

static void blk_account_io_set_attach_target(struct biostacks_bpf *obj)
{
	if (fentry_can_attach("blk_account_io_start", NULL)) {
		bpf_program__set_attach_target(obj->progs.blk_account_io_start,
					       0, "blk_account_io_start");
		bpf_program__set_attach_target(obj->progs.blk_account_io_done,
					       0, "blk_account_io_done");
	} else if (fentry_can_attach("__blk_account_io_start", NULL)) {
		bpf_program__set_attach_target(obj->progs.blk_account_io_start,
					       0, "__blk_account_io_start");
		bpf_program__set_attach_target(obj->progs.blk_account_io_done,
					       0, "__blk_account_io_done");
	} else {
		disable_blk_account_io_fentry(obj);
	}
}

int main(int argc, char *argv[])
{
	struct partitions *partitions = NULL;
	const struct partition *partition;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct ksyms *ksyms = NULL;
	struct biostacks_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = biostacks_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	partitions = partitions__load();
	if (!partitions) {
		warning("Failed to load partitions info\n");
		goto cleanup;
	}

	if (env.disk) {
		partition = partitions__get_by_name(partitions, env.disk);
		if (!partition) {
			warning("Invalid partition name: not exist\n");
			goto cleanup;
		}
		obj->rodata->filter_dev = true;
		obj->rodata->target_dev = partition->dev;
	}

	obj->rodata->target_ms = env.milliseconds;

	if (has_block_io_tracepoints()) {
		disable_blk_io_kprobe(obj);
		disable_blk_account_io_fentry(obj);
	} else if (has_block_io_fentry()) {
		disable_blk_io_tracepoints(obj);
		disable_blk_io_kprobe(obj);
		blk_account_io_set_attach_target(obj);
	} else {
		disable_blk_io_tracepoints(obj);
		disable_blk_account_io_fentry(obj);
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("Failed to load kallsyms\n");
		goto cleanup;
	}

	if (!ksyms__get_symbol(ksyms, "blk_account_io_merge_bio"))
		bpf_program__set_autoload(obj->progs.blk_account_io_merge_bio, false);

	err = biostacks_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = biostacks_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing block I/O with init stacks. Hit Ctrl-C to end.\n");
	sleep(env.duration);
	print_map(ksyms, partitions, bpf_map__fd(obj->maps.hists));

cleanup:
	biostacks_bpf__destroy(obj);
	ksyms__free(ksyms);
	partitions__free(partitions);

	return err != 0;
}
