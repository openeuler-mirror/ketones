// SPDX-License-Identifier: GPL-2.0
#include "commons.h"
#include "vfsstat.h"
#include "vfsstat.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

static volatile sig_atomic_t exiting;

const char *argp_program_version = "vfsstat 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"\nvfsstat: Count some VFS calls\n"
"\n"
"EXAMPLES:\n"
"    vfsstat      # interval one second\n"
"    vfsstat 5 3  # interval five seconds, three output lines\n";

static char args_doc[] = "[interval [count]]";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static struct env {
	bool verbose;
	int count;
	int interval;
} env = {
	.interval = 1, /* once a second */
	.count = 99999999,
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
	case ARGP_KEY_ARG:
		switch (state->arg_num) {
		case 0:
			env.interval = argp_parse_long(key, arg, state);
			break;
		case 1:
			env.count = argp_parse_long(key, arg, state);
			break;
		default:
			argp_usage(state);
			break;
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

static const char *stat_types_names[] = {
	[S_READ] = "READ",
	[S_WRITE] = "WRITE",
	[S_FSYNC] = "FSYNC",
	[S_OPEN] = "OPEN",
	[S_CREATE] = "CREATE",
	[S_UNLINK] = "UNLINK",
	[S_MKDIR] = "MKDIR",
	[S_RMDIR] = "RMDIR",
};

static void print_header(void)
{
	printf("%-8s ", "TIME");
	for (int i = 0; i < S_MAXSTAT; i++)
		printf(" %6s/s", stat_types_names[i]);
	printf("\n");
}

static void print_and_reset_stats(__u64 stats[S_MAXSTAT])
{
	char s[16];
	__u64 val;

	printf("%-8s ", strftime_now(s, sizeof(s), "%H:%M:%S"));
	for (int i = 0; i < S_MAXSTAT; i++) {
		val = __atomic_exchange_n(&stats[i], 0, __ATOMIC_RELAXED);
		printf(" %8llu", val / env.interval);
	}
	printf("\n");
}

static void sig_handler(int sig)
{
	exiting = 1;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
		.args_doc = args_doc
	};
	DEFINE_SKEL_OBJECT(skel);
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

	skel = SKEL_OPEN();
	if (!skel) {
		warning("Failed to open BPF objects\n");
		goto cleanup;
	}

	/* It fallbacks to kprobes when kernel does not support fentry. */
	if (fentry_can_attach("vfs_read", NULL)) {
		bpf_program__set_autoload(skel->progs.kprobe_vfs_read, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_write, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_fsync, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_open, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_create, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_unlink, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_mkdir, false);
		bpf_program__set_autoload(skel->progs.kprobe_vfs_rmdir, false);
	} else {
		bpf_program__set_autoload(skel->progs.fentry_vfs_read, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_write, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_fsync, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_open, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_create, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_unlink, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_mkdir, false);
		bpf_program__set_autoload(skel->progs.fentry_vfs_rmdir, false);
	}

	err = SKEL_LOAD(skel);
	if (err) {
		warning("Failed to load BPF skelect: %d\n", err);
		goto cleanup;
	}

	if (!skel->bss) {
		warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = SKEL_ATTACH(skel);
	if (err) {
		warning("Failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	print_header();

	while (!exiting) {
		sleep(env.interval);
		print_and_reset_stats(skel->bss->stats);

		if (--env.count == 0)
			break;
	}

cleanup:
	SKEL_DESTROY(skel);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
