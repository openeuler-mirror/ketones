// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "opensnoop.h"
#include "opensnoop.skel.h"
#include "compat.h"

#include <libgen.h>
#include <fcntl.h>
#include <pwd.h>

#ifdef USE_BLAZESYM
#include "blazesym.h"
#endif

static volatile sig_atomic_t exiting;

#ifdef USE_BLAZESYM
static blazesym *symbolizer;
#endif

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
#ifdef USE_BLAZESYM
	bool callers;
#endif
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
#ifdef USE_BLAZESYM
"                 [-n NAME] [-e] [-c]\n"
#else
"                 [-n NAME] [-e]\n"
#endif
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
#ifdef USE_BLAZESYM
"    ./opensnoop -c        # show calling functions\n"
#endif
"";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Duration to trace" },
	{ "extended-fields", 'e', NULL, 0, "Print extended fields" },
	{ "format-extended-fields", 'E', NULL, 0, "Print formated extended fields" },
	{ "name", 'n', "NAME", 0, "Trace process names containing this" },
	{ "pid", 'p', "PID", 0, "Process PID to trace" },
	{ "tid", 't', "TID", 0, "Thread ID to trace " },
	{ "timestamp", 'T', NULL, 0, "Print timestamp" },
	{ "uid", 'u', "UID", 0, "User ID to trace" },
	{ "print-uid", 'U', NULL, 0, "Print UID" },
	{ "print-ppid", 'P', NULL, 0, "Print parent pid" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "failed", 'x', NULL, 0, "Failed opens only" },
#ifdef USE_BLAZESYM
	{ "callers", 'c', NULL, 0, "Show calling functions" },
#endif
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
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
#ifdef USE_BLAZESYM
	case 'c':
		env.callers = true;
		break;
#endif
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
	const struct event *e = data;
	int fd, err, sps_cnt;
	const char *program_name = basename((char *)ctx);
#ifdef USE_BLAZESYM
	blazesym_sym_src_cfg src_cfg;
	const blazesym_result *result = NULL;
	const blazesym_csym *sym;

	src_cfg.src_type = BLAZESYM_SRC_T_PROCESS;
	src_cfg.params.process.pid = e->pid;
#endif

	/* name filtering is currently done in user space */
	if (env.name && strstr(e->comm, env.name) == NULL)
		return 0;

	/* skip this program */
	if (!strcmp(program_name, e->comm))
		return 0;

	/* prepare fileds */
	if (e->ret >= 0) {
		fd = e->ret;
		err = 0;
	} else {
		fd = -1;
		err = - e->ret;
	}

#ifdef USE_BLAZESYM
	if (env.callers)
		result = blazesym_symbolize(symbolizer, &src_cfg, 1,
					    (const uint64_t *)&e->callers, 2);
#endif

	/* print output */
	sps_cnt = 0;
	if (env.timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%-8s ", ts);
		sps_cnt += 9;
	}

	if (env.print_uid) {
		struct passwd *passwd;
		passwd = getpwuid(e->uid);
		if (!passwd) {
			warning("getpwuid() failed: %s\n", strerror(errno));
			return -1;
		}
		printf("%-7s ", passwd->pw_name);
		sps_cnt += 8;
	}

	if (env.print_ppid) {
		printf("%-7d ", e->ppid);
		sps_cnt += 7;
	}

	printf("%-7d %-16s %3d %3d ", e->pid, e->comm, fd, err);
	sps_cnt += 7 + 17 + 4 + 4;

	if (env.extended && !env.fuller_extended) {
		printf("%08o %08o ", e->flags, e->modes);
		sps_cnt += 18;
	}
	printf("%s\n", e->fname);

	if (env.fuller_extended) {
		parse_open_flags(e->flags, sps_cnt);
		parse_open_modes(e->modes, sps_cnt);
		printf("\n");
	}

#ifdef USE_BLAZESYM
	for (int i = 0; result && i < result->size; i++) {
		if (result->entries[i].size == 0)
			continue;
		sym = &result->entries[i].syms[0];

		for (int j = 0; j < sps_cnt; j++)
			printf(" ");
		if (sym->line_no)
			printf("%s:%ld\n", sym->symbol, sym->line_no);
		else
			printf("%s\n", sym->symbol);
	}

	blazesym_result_free(result);
#endif

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
	struct opensnoop_bpf *obj;
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

	obj = opensnoop_bpf__open_opts(&open_opts);
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

	err = opensnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = opensnoop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, argv[0]);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

#ifdef USE_BLAZESYM
	if (env.callers)
		symbolizer = blazesym_new();
#endif

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
#ifdef USE_BLAZESYM
	if (env.callers)
		printf("/CALLER");
#endif
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
	opensnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
#ifdef USE_BLAZESYM
	blazesym_free(symbolizer);
#endif

	return err != 0;
}
