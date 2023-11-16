// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "biolatency.h"
#include "biolatency.skel.h"
#include "trace_helpers.h"
#include "blk_types.h"
#include <sys/resource.h>

static struct env {
	char	*disk;
	time_t	interval;
	int	times;
	bool	timestamp;
	bool	queued;
	bool	per_disk;
	bool	per_flag;
	bool	milliseconds;
	bool	verbose;
	char	*cgroupspath;
	bool	cg;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "biolatency 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Summarize block device I/O latency as a histogram.\n"
"\n"
"USAGE: biolatency [--help] [-T] [-m] [-Q] [-D] [-F] [-d DISK] [-c CG] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    biolatency              # summarize block I/O latency as a histogram\n"
"    biolatency 1 10         # print 1 second summaries, 10 times\n"
"    biolatency -mT 1        # 1s summaries, milliseconds, and timestamps\n"
"    biolatency -Q           # include OS queued time in I/O time\n"
"    biolatency -D           # show each disk device separately\n"
"    biolatency -F           # show I/O flags separately\n"
"    biolatency -d sdc       # Trace sdc only\n"
"    biolatency -c CG        # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "milliseonds", 'm', NULL, 0, "Millisecond histogram" },
	{ "queued", 'Q', NULL, 0, "Include OS queued time in I/O time" },
	{ "disk", 'D', NULL, 0, "Print a histogram per disk device" },
	{ "flag", 'F', NULL, 0, "Print a histogram per set of I/O flags" },
	{ "disk", 'd', "DISK", 0, "Trace this disk only" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
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
	case 'T':
		env.timestamp = true;
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'Q':
		env.queued = true;
		break;
	case 'D':
		env.per_disk = true;
		break;
	case 'F':
		env.per_flag = true;
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
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
			env.interval = strtol(arg, NULL, 10);
			if (errno || env.interval <= 0) {
				warning("Invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 10);
			if (errno || env.times <= 0) {
				warning("Invalid times\n");
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
{
	exiting = 1;
}

static void print_cmd_flags(int cmd_flags)
{
	static struct {
		int bit;
		const char *str;
	} flags[] = {
		{ REQ_NOWAIT, "NoWait-" },
		{ REQ_BACKGROUND, "Background-" },
		{ REQ_RAHEAD, "ReadAhead-" },
		{ REQ_PREFLUSH, "PreFlush-" },
		{ REQ_FUA, "FUA-" },
		{ REQ_INTEGRITY, "Integrity-" },
		{ REQ_IDLE, "Idle-" },
		{ REQ_NOMERGE, "NoMerge-" },
		{ REQ_PRIO, "Priority-" },
		{ REQ_META, "Metadata-" },
		{ REQ_SYNC, "Sync-" },
	};

	static const char *ops[] = {
		[REQ_OP_READ] = "Read",
		[REQ_OP_WRITE] = "Write",
		[REQ_OP_FLUSH] = "Flush",
		[REQ_OP_DISCARD] = "Discard",
		[REQ_OP_SECURE_ERASE] = "SecureErase",
		[REQ_OP_ZONE_RESET] = "ZoneReset",
		[REQ_OP_WRITE_SAME] = "WriteSame",
		[REQ_OP_ZONE_RESET_ALL] = "ZoneResetAll",
		[REQ_OP_WRITE_ZEROES] = "WriteZeroes",
		[REQ_OP_ZONE_OPEN] = "ZoneOpen",
		[REQ_OP_ZONE_CLOSE] = "ZoneClose",
		[REQ_OP_ZONE_FINISH] = "ZoneFinish",
		[REQ_OP_SCSI_IN] = "SCSIIn",
		[REQ_OP_SCSI_OUT] = "SCSIOut",
		[REQ_OP_DRV_IN] = "DrvIn",
		[REQ_OP_DRV_OUT] = "DrvOut",
	};

	printf("flags = ");

	for (int i = 0; i < ARRAY_SIZE(flags); i++) {
		if (cmd_flags & flags[i].bit)
			printf("%s", flags[i].str);
	}

	if ((cmd_flags & REQ_OP_MASK) < ARRAY_SIZE(ops))
		printf("%s", ops[cmd_flags & REQ_OP_MASK]);
	else
		printf("Unknown");
}

static int print_log2_hists(struct bpf_map *hists, struct partitions *partitions)
{
	struct hist_key lookup_key = { .cmd_flags = -1 }, next_key;
	const char *units = env.milliseconds ? "msecs" : "usecs";
	const struct partition *partition;
	int err, fd = bpf_map__fd(hists);
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			warning("Failed to lookup hist: %d\n", err);
			return -1;
		}
		if (env.per_disk) {
			partition = partitions__get_by_dev(partitions,
							  next_key.dev);
			printf("\ndisk = %s\t", partition ? partition->name :
			       "Unknown");
		}
		if (env.per_flag)
			print_cmd_flags(next_key.cmd_flags);
		printf("\n");
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key.cmd_flags = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			warning("Failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

/*
 * BTF has a func proto for each tracepoint, let's check it like
 *   typedef void (*btf_trace_block_rq_issue)(void *, struct request *);
 *
 * Actually it's a typedef for a pointer to the func proto.
 */
static bool has_block_rq_issue_single_arg(void)
{
	const struct btf *btf = btf__load_vmlinux_btf();
	const struct btf_type *t1, *t2, *t3;
	__u32 type_id;
	bool ret = true;	// assuming recent kernels

	type_id = btf__find_by_name_kind(btf, "btf_trace_block_rq_issue",
					 BTF_KIND_TYPEDEF);
	if ((__s32)type_id < 0)
		return ret;

	t1 = btf__type_by_id(btf, type_id);
	if (!t1)
		return ret;

	t2 = btf__type_by_id(btf, t1->type);
	if (!t2 || !btf_is_ptr(t2))
		return ret;

	t3 = btf__type_by_id(btf, t2->type);
	if (t3 && btf_is_func_proto(t3))
		ret = (btf_vlen(t3) == 2);	// ctx + arg

	return ret;
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct biolatency_bpf *obj;
	int cgfd = -1;
	struct partitions *partitions = NULL;
	const struct partition *partition;

	int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = biolatency_bpf__open();
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

	obj->rodata->target_per_disk = env.per_disk;
	obj->rodata->target_per_flag = env.per_flag;
	obj->rodata->target_ms = env.milliseconds;
	obj->rodata->target_queued = env.queued;
	obj->rodata->filter_memcg = env.cg;
	obj->rodata->target_single = has_block_rq_issue_single_arg();

	if (probe_tp_btf("block_rq_insert")) {
		bpf_program__set_autoload(obj->progs.block_rq_insert_raw, false);
		bpf_program__set_autoload(obj->progs.block_rq_issue_raw, false);
		bpf_program__set_autoload(obj->progs.block_rq_complete_raw, false);
		if (!env.queued)
			bpf_program__set_autoload(obj->progs.block_rq_insert_btf, false);
	} else {
		bpf_program__set_autoload(obj->progs.block_rq_insert_btf, false);
		bpf_program__set_autoload(obj->progs.block_rq_issue_btf, false);
		bpf_program__set_autoload(obj->progs.block_rq_complete_btf, false);
		if (!env.queued)
			bpf_program__set_autoload(obj->progs.block_rq_insert_raw, false);
	}

	err = biolatency_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (env.cg) {
		int idx = 0;
		int cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);
		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			warning("Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			warning("Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	err = biolatency_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing block device I/O... Hit Ctrl-C to end.\n");

	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			char ts[32] = {};

			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s\n", ts);
		}

		err = print_log2_hists(obj->maps.hists, partitions);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	biolatency_bpf__destroy(obj);
	partitions__free(partitions);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
