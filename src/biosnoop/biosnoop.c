// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "blk_types.h"
#include "biosnoop.h"
#include "biosnoop.skel.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;

static struct env {
	__u64 min_lat_ms;
	char *disk;
	int duration;
	bool timestamp;
	bool queued;
	bool verbose;
	char *cgroupspath;
	bool cg;
} env;

static volatile __u64 start_ts;

const char *argp_program_version = "biosnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace block I/O.\n"
"\n"
"USAGE: biosnoop [--help] [-d DISK] [-c CG] [-Q]\n"
"\n"
"EXAMPLES:\n"
"    biosnoop              # trace all block I/O\n"
"    biosnoop -Q           # include OS queued time in I/O time\n"
"    biosnoop -t           # use timestamps instead\n"
"    biosnoop 10           # trace for 10 seconds only\n"
"    biosnoop -d sdc       # trace sdc only\n"
"    biosnoop -c CG        # Trace process under cgroupsPath CG\n"
"    biosnoop -m 1         # trace for slower than 1ms\n";

static const struct argp_option opts[] = {
	{ "queued", 'Q', NULL, 0, "Include OS queued time in I/O time", 0 },
	{ "disk", 'd', "DISK", 0, "Trace this disk only", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified/CG", 0, "Trace process in cgroup path", 0 },
	{ "min", 'm', "MIN", 0, "Min latency to trace, in ms", 0 },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'Q':
		env.queued = true;
		break;
	case 'c':
		env.cg = true;
		env.cgroupspath = arg;
		break;
	case 'd':
		env.disk = arg;
		if (strlen(arg) + 1 > DISK_NAME_LEN) {
			warning("Invalid disk name %s: too long\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		env.min_lat_ms = argp_parse_long(key, arg, state);
		break;
	case 't':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0) {
			env.duration = argp_parse_long(key, arg, state);
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
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static void blk_fill_rwbs(char *rwbs, unsigned int op)
{
	int i = 0;

	if (op & REQ_PREFLUSH)
		rwbs[i++] = 'F';

	switch (op & REQ_OP_MASK) {
	case REQ_OP_WRITE:
	case REQ_OP_WRITE_SAME:
		rwbs[i++] = 'W';
		break;
	case REQ_OP_DISCARD:
		rwbs[i++] = 'D';
		break;
	case REQ_OP_SECURE_ERASE:
		rwbs[i++] = 'D';
		rwbs[i++] = 'E';
		break;
	case REQ_OP_FLUSH:
		rwbs[i++] = 'F';
		break;
	case REQ_OP_READ:
		rwbs[i++] = 'R';
		break;
	default:
		rwbs[i++] = 'N';
		break;
	}

	if (op & REQ_FUA)
		rwbs[i++] = 'F';
	if (op & REQ_RAHEAD)
		rwbs[i++] = 'A';
	if (op & REQ_SYNC)
		rwbs[i++] = 'S';
	if (op & REQ_META)
		rwbs[i++] = 'M';

	rwbs[i] = '\0';
}

static struct partitions *partitions;

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct partition *partition;
	struct event e;
	char rwbs[RWBS_LEN];

	if (data_sz < sizeof(e)) {
		warning("Packet too small\n");
		return;
	}

	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	if (env.timestamp) {
		char ts[16];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%-8s ", ts);
	} else {
		if (!start_ts)
			start_ts = e.ts;
		printf("%-11.6f ", (e.ts - start_ts) / 1000000000.0);
	}

	blk_fill_rwbs(rwbs, e.cmd_flags);
	partition = partitions__get_by_dev(partitions, e.dev);
	printf("%-14.14s %-7d %-7s %-4s %-10lld %-7d ",
	       e.comm, e.pid, partition ? partition->name : "Unknown", rwbs,
	       e.sector, e.len);
	if (env.queued)
		printf("%7.3f ", e.qdelta != -1 ?
			e.qdelta / 1000000.0 : -1);
	printf("%7.3f\n", e.delta / 1000000.0);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void blk_account_io_set_attach_target(struct biosnoop_bpf *obj)
{
	if (fentry_can_attach("blk_account_io_start", NULL)) {
		bpf_program__set_attach_target(obj->progs.blk_account_io_start, 0,
					       "blk_account_io_start");
		bpf_program__set_autoload(obj->progs.kprobe_blk_account_io_start, false);
	} else if (fentry_can_attach("__blk_account_io_start", NULL)) {
		bpf_program__set_attach_target(obj->progs.blk_account_io_start, 0,
					       "__blk_account_io_start");
		bpf_program__set_autoload(obj->progs.kprobe_blk_account_io_start, false);
	} else {
		bpf_program__set_autoload(obj->progs.blk_account_io_start, false);
	}
}

int main(int argc, char *argv[])
{
	const struct partition *partition;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct ksyms *ksyms = NULL;
	DEFINE_SKEL_OBJECT(obj);
	__u64 time_end = 0;
	int err;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = SKEL_OPEN();
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
	obj->rodata->target_queued = env.queued;
	obj->rodata->filter_memcg = env.cg;
	obj->rodata->min_ns = env.min_lat_ms * 1000000;

	if (tracepoint_exists("block", "block_io_start")) {
		bpf_program__set_autoload(obj->progs.blk_account_io_start, false);
		bpf_program__set_autoload(obj->progs.kprobe_blk_account_io_start, false);
	} else {
		bpf_program__set_autoload(obj->progs.block_io_start, false);
		blk_account_io_set_attach_target(obj);
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		err = -ENOMEM;
		warning("Failed to load kallsyms\n");
		goto cleanup;
	}

	if (!ksyms__get_symbol(ksyms, "blk_account_io_merge_bio"))
		bpf_program__set_autoload(obj->progs.blk_account_io_merge_bio, false);

	if (env.queued) {
		if (probe_tp_btf("block_rq_insert"))
			bpf_program__set_autoload(obj->progs.block_rq_insert_raw, false);
		else
			bpf_program__set_autoload(obj->progs.block_rq_insert, false);
	} else {
		bpf_program__set_autoload(obj->progs.block_rq_insert_raw, false);
		bpf_program__set_autoload(obj->progs.block_rq_insert, false);
	}

	if (probe_tp_btf("block_rq_complete")) {
		bpf_program__set_autoload(obj->progs.block_rq_complete_raw, false);
		bpf_program__set_autoload(obj->progs.block_rq_issue_raw, false);
	} else {
		bpf_program__set_autoload(obj->progs.block_rq_complete, false);
		bpf_program__set_autoload(obj->progs.block_rq_issue, false);
	}

	err = SKEL_LOAD(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (env.cg) {
		int idx = 0;
		int cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);

		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			warning("Failed to opening cgroup path: %s\n", env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			warning("Failed to adding target cgroup to map\n");
			goto cleanup;
		}
	}

	err = SKEL_ATTACH(obj);
	if (err) {
		warning("Failed to attach BPF programs\n");
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warning("Failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (env.timestamp) {
		printf("%-8s ", "TIMESTAMP");
	} else {
		printf("%-11s ", "TIME(s)");
	}
	printf("%-14s %-7s %-7s %-4s %-10s %-7s ",
	       "COMM", "PID", "DISK", "T", "SECTOR", "BYTES");
	if (env.queued)
		printf("%7s ", "QUE(ms)");
	printf("%7s\n", "LAT(ms)");

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal hander: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
		if (env.duration && get_ktime_ns() > time_end)
			break;
	}

cleanup:
	perf_buffer__free(pb);
	SKEL_DESTROY(obj);
	ksyms__free(ksyms);
	partitions__free(partitions);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
