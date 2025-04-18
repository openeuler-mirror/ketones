// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "opensnoop.h"
#include "opensnoop.skel.h"
#include "compat.h"

#include <libgen.h>
#include <fcntl.h>

static volatile sig_atomic_t exiting;

static struct env {
	pid_t pid;
	pid_t tid;
	uid_t uid;
	int duration;
	bool verbose;
	bool timestamp;
	bool print_uid;
	bool print_ppid;
	bool extended;
	bool fuller_extended;
	bool failed;
	char *name;
} env = {
	.uid = INVALID_UID
};

struct openflag {
	int flag;
	const char *name;
};

static struct openflag openflags[] = {
	{ O_RDONLY, "O_RDONLY" },
	{ O_WRONLY, "O_WRONLY" },
	{ O_RDWR, "O_RDWR" },
	{ O_APPEND, "O_APPEND" },
	{ O_CREAT, "O_CREAT" },
	{ O_CLOEXEC, "O_CLOEXEC" },
	{ O_EXCL, "O_EXCL" },
	{ O_TRUNC, "O_TRUNC" },
	{ O_DIRECTORY, "O_DIRCTORY" },
	{ O_NONBLOCK, "O_NONBLOCK" },
	{ O_DSYNC, "O_DSYNC" },
	{ O_SYNC, "O_SYNC" },
	{ O_NOCTTY, "O_NOCTTY" },
	{ O_NOFOLLOW, "O_NOFOLLOW" },
	{ O_RSYNC, "O_RSYNC" },
};

struct openmode {
	unsigned short mode;
	const char *name;
};

static struct openmode openmodes[] = {
	{ S_IRWXU, "S_IRWXU" },
	{ S_IRUSR, "S_IRUSR" },
	{ S_IWUSR, "S_IWUSR" },
	{ S_IXUSR, "S_IXUSR" },
	{ S_IRWXG, "S_IRWXG" },
	{ S_IRGRP, "S_IRGRP" },
	{ S_IWGRP, "S_IWGRP" },
	{ S_IXGRP, "S_IXGRP" },
	{ S_IRWXO, "S_IRWXO" },
	{ S_IROTH, "S_IROTH" },
	{ S_IWOTH, "S_IWOTH" },
	{ S_IXOTH, "S_IXOTH" },
	{ S_ISUID, "S_ISUID" },
	{ S_ISGID, "S_ISGID" },
	{ S_ISVTX, "S_ISVTX" },
};

const char *argp_program_version = "opensnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace open family syscalls\n"
"\n"
"USAGE: opensnoop [-h] [-T] [-U] [-x] [-P] [-p PID] [-t TID] [-u UID] [-d DURATION]\n"
"                 [-n NAME] [-e]\n"
"\n"
"EXAMPLES:\n"
"    ./opensnoop           # trace all open() syscalls\n"
"    ./opensnoop -T        # include timestamps\n"
"    ./opensnoop -U        # include UID\n"
"    ./opensnoop -P        # print parent pid\n"
"    ./opensnoop -x        # only show failed opens\n"
"    ./opensnoop -p 181    # only trace PID 181\n"
"    ./opensnoop -t 123    # only trace TID 123\n"
"    ./opensnoop -u 1000   # only trace UID 1000\n"
"    ./opensnoop -d 10     # trace for 10 seconds only\n"
"    ./opensnoop -n main   # only print process names containing \"main\"\n"
"    ./opensnoop -e        # show extended fields\n"
"    ./opensnoop -E        # show formated extended fields\n"
"";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Duration to trace", 0 },
	{ "extended-fields", 'e', NULL, 0, "Print extended fields", 0 },
	{ "format-extended-fields", 'E', NULL, 0, "Print formated extended fields", 0 },
	{ "name", 'n', "NAME", 0, "Trace process names containing this", 0 },
	{ "pid", 'p', "PID", 0, "Process PID to trace", 0 },
	{ "tid", 't', "TID", 0, "Thread ID to trace ", 0 },
	{ "timestamp", 'T', NULL, 0, "Print timestamp", 0 },
	{ "uid", 'u', "UID", 0, "User ID to trace", 0 },
	{ "print-uid", 'U', NULL, 0, "Print UID", 0 },
	{ "print-ppid", 'P', NULL, 0, "Print parent pid", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "failed", 'x', NULL, 0, "Failed opens only", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'e':
		env.extended = true;
		break;
	case 'E':
		env.fuller_extended = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'U':
		env.print_uid = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'x':
		env.failed = true;
		break;
	case 'd':
		env.duration = argp_parse_long(key, arg, state);
		break;
	case 'n':
		env.name = arg;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'P':
		env.print_ppid = true;
		break;
	case 't':
		env.tid = argp_parse_pid(key, arg, state);
		break;
	case 'u':
		errno = 0;
		env.uid = strtol(arg, NULL, 10);
		if (errno || env.uid < 0 || env.uid >= INVALID_UID) {
			warning("Invalid UID %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
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

static void parse_open_flags(int flag, int sps_cnt)
{
	char flags_string[1024] = {0};

	for (int j = 0; j < ARRAY_SIZE(openflags); j++) {
		if (!(flag & openflags[j].flag))
			continue;
		if (flags_string[0])
			strcat(flags_string, " | ");
		strcat(flags_string, openflags[j].name);
	}
	if (strlen(flags_string) == 0)
		return;

	for (int j = 0; j < sps_cnt; j++)
	       printf(" ");

	printf("FLAGS: %s\n", flags_string);
}

static void parse_open_modes(unsigned short mode, int sps_cnt)
{
	char modes_string[1024] = {0};

	for (int j = 0; j < ARRAY_SIZE(openmodes); j++) {
		if (!(mode & openmodes[j].mode))
			continue;
		if (modes_string[0])
			strcat(modes_string, " | ");
		strcat(modes_string, openmodes[j].name);
	}
	if (strlen(modes_string) == 0)
		return;

	for (int j = 0; j < sps_cnt; j++)
	       printf(" ");

	printf("MODES: %s\n", modes_string);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event e;
	int fd, err, sps_cnt;
	const char *program_name = basename((char *)ctx);

	if (data_sz < sizeof(e)) {
		warning("Packet too small\n");
		return 0;
	}

	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&e, data, sizeof(e));

	/* name filtering is currently done in user space */
	if (env.name && strstr(e.comm, env.name) == NULL)
		return 0;

	/* skip this program */
	if (!strcmp(program_name, e.comm))
		return 0;

	/* prepare fileds */
	if (e.ret >= 0) {
		fd = e.ret;
		err = 0;
	} else {
		fd = -1;
		err = - e.ret;
	}

	/* print output */
	sps_cnt = 0;
	if (env.timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%-8s ", ts);
		sps_cnt += 9;
	}

	if (env.print_uid) {
		printf("%-7s ", get_uid_name(e.uid));
		sps_cnt += 8;
	}

	if (env.print_ppid) {
		printf("%-7d ", e.ppid);
		sps_cnt += 7;
	}

	printf("%-7d %-16s %3d %3d ", e.pid, e.comm, fd, err);
	sps_cnt += 7 + 17 + 4 + 4;

	if (env.extended && !env.fuller_extended) {
		printf("%08o %08o ", e.flags, e.modes);
		sps_cnt += 18;
	}
	printf("%s\n", e.fname);

	if (env.fuller_extended) {
		parse_open_flags(e.flags, sps_cnt);
		parse_open_modes(e.modes, sps_cnt);
		printf("\n");
	}

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
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	DEFINE_SKEL_OBJECT(obj);
	__u64 time_end = 0;
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
		warning("Failed to open BPF object\n");
		return 1 ;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = -errno;
		warning("Failed to create ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	obj->rodata->target_tgid = env.pid;
	obj->rodata->target_pid = env.tid;
	obj->rodata->target_uid = env.uid;
	obj->rodata->target_failed = env.failed;

	/* aarch64 and riscv64 don't have open syscall */
	if (!tracepoint_exists("syscalls", "sys_enter_open")) {
		bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_enter_open, false);
		bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_exit_open, false);
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

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, argv[0]);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	/* print headers */
	if (env.timestamp)
		printf("%-8s ", "TIME");
	if (env.print_uid)
		printf("%-7s ", "UID");
	if (env.print_ppid)
		printf("%-7s ", "PPID");
	printf("%-7s %-16s %3s %3s ", "PID", "COMM", "FD", "ERR");
	if (env.extended)
		printf("%-8s %-8s ", "FLAGS", "MODES");
	printf("%s", "PATH");
	printf("\n");

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		if (env.duration && get_ktime_ns() > time_end)
			goto cleanup;
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	SKEL_DESTROY(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
