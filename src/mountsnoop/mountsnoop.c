// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "mountsnoop.h"
#include "mountsnoop.skel.h"
#include "btf_helpers.h"
#include "compat.h"

static volatile sig_atomic_t exiting;

static pid_t target_pid = 0;
static bool emit_timestamp = false;
static bool output_vertically = false;
static bool verbose = false;
static const char *flag_names[] = {
	[0] = "MS_RDONLY",
	[1] = "MS_NOSUID",
	[2] = "MS_NODEV",
	[3] = "MS_NOEXEC",
	[4] = "MS_SYNCHRONOUS",
	[5] = "MS_REMOUNT",
	[6] = "MS_MANDLOCK",
	[7] = "MS_DIRSYNC",
	[8] = "MS_NOSYMFOLLOW",
	[9] = "MS_NOATIME",
	[10] = "MS_NODIRATIME",
	[11] = "MS_BIND",
	[12] = "MS_MOVE",
	[13] = "MS_REC",
	[14] = "MS_VERBOSE",
	[15] = "MS_SLIENT",
	[16] = "MS_POSIXACL",
	[17] = "MS_UNBINDABLE",
	[18] = "MS_PRIVATE",
	[19] = "MS_SLAVE",
	[20] = "MS_SHARED",
	[21] = "MS_RELATIME",
	[22] = "MS_KERNMOUNT",
	[23] = "MS_I_VERSION",
	[24] = "MS_STRICTATIME",
	[25] = "MS_LAZYTIME",
	[26] = "MS_SUBMOUNT",
	[27] = "MS_NOREMOTELOCK",
	[28] = "MS_NOSEC",
	[29] = "MS_BORN",
	[30] = "MS_ACTIVE",
	[32] = "MS_NOUSER",
};

const char *argp_program_version = "mountsnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace mount and umount syscalls.\n"
"\n"
"USAGE: mountsnoop [-h] [-T] [-p PID] [-v]\n"
"\n"
"EXAMPLES:\n"
"    mountsnoop         # trace mount and umount syscalls\n"
"    mountsnoop -d      # detailed output (one line per column value)\n"
"    mountsnoop -p 1216 # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output", 0 },
	{ NULL, 't', NULL, OPTION_ALIAS, "Include timestamp on output", 0 },
	{ "detailed", 'd', NULL, 0, "Output result in detail mode", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		target_pid = argp_parse_pid(key, arg, state);
		break;
	case 'T':
	case 't':
		emit_timestamp = true;
		break;
	case 'd':
		output_vertically = true;
		break;
	case 'v':
		verbose = true;
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
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static const char *strflags(__u64 flags)
{
	static char str[512];

	if (!flags)
		return "0x0";

	str[0] = 0;

	for (int i = 0; i < ARRAY_SIZE(flag_names); i++) {
		if (!((1 << i) & flags))
			continue;
		if (str[0])
			strcat(str, " | ");
		strcat(str, flag_names[i]);
	}
	return str;
}

static const char *gen_call(const struct event *e)
{
	static char call[10240] = {};

	if (e->op == UMOUNT) {
		snprintf(call, sizeof(call), "umount(\"%s\", %s) = %s",
			 e->dest, strflags(e->flags), strerrno(e->ret));
	} else {
		snprintf(call, sizeof(call), "mount(\"%s\", \"%s\", \"%s\", %s, \"%s\") = %s",
			 e->src, e->dest, e->fs, strflags(e->flags), e->data, strerrno(e->ret));
	}
	return call;
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct event *e = data;
	char ts[32];
	const char *indent;
	static const char *op_name[] = {
		[MOUNT] = "MOUNT",
		[UMOUNT] = "UMOUNT",
	};

	if (emit_timestamp) {
		strftime_now(ts, sizeof(ts), "%H:%M:%S ");
		printf("%s", ts);
		indent = "   ";
	} else {
		indent = "";
	}

	if (!output_vertically) {
		printf("%-16s %-7d %-7d %-11u %s\n",
		       e->comm, e->pid, e->tid, e->mnt_ns, gen_call(e));
		return 0;
	}

	if (emit_timestamp)
		printf("\n");
	printf("%sPID:\t\t%d\n", indent, e->pid);
	printf("%sTID:\t\t%d\n", indent, e->tid);
	printf("%sCOMM:\t%s\n", indent, e->comm);
	printf("%sOP:\t\t%s\n", indent, op_name[e->op]);
	printf("%sRET:\t\t%s\n", indent, strerrno(e->ret));
	printf("%sLAT:\t\t%lldus\n", indent, e->delta / 1000);
	printf("%sMNT_NS:\t%u\n", indent, e->mnt_ns);
	printf("%sFS:\t\t%s\n", indent, e->fs);
	printf("%sSOURCE:\t%s\n", indent, e->src);
	printf("%sTARGET:\t%s\n", indent, e->dest);
	printf("%sDATA:\t%s\n", indent, e->data);
	printf("%sFLAGS:\t%s\n", indent, strflags(e->flags));
	printf("\n");

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on cpu #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	DEFINE_SKEL_OBJECT(obj);
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

	obj = SKEL_OPEN_OPTS(&open_opts);
	if (!obj) {
		warning("Failed to open BPF objects\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		warning("Failed to create ring/perf buffer: %d\n", err);
		goto cleanup;
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

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (!output_vertically) {
		if (emit_timestamp)
			printf("%-8s ", "TIME");
		printf("%-16s %-7s %-7s %-11s %s\n", "COMM", "PID", "TID", "MNT_NS", "CALL");
	}

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	SKEL_DESTROY(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
