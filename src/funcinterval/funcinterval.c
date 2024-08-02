// SPDX-License-Identifier: GPL-2.0
// Based on funcinterval.py - Edward Wu

#include "commons.h"
#include "funcinterval.skel.h"
#include "funcinterval.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

static volatile sig_atomic_t exiting;
const char *attach_type[] = {"KPROBE", "UPROBE", "TRACEPOINT"};

enum TRACE_TYPE {
	KPROBE,
	UPROBE,
	TRACEPOINT,
};

static struct env {
	bool verbose;
	bool milliseconds;
	int interval;
	pid_t pid;
	bool timestamp;
	const char *functions;
} env = {
	.interval = 99999999,
	.verbose = false,
	.milliseconds = false,
};

const char *argp_program_version = "funcinterval 0.1";
const char *argp_program_bug_address = "Yang Feng <yangfeng@kylinos.cn>";
const char argp_program_doc[] =
"funcinterval   Time interval between the same function, tracepoint as a histogram.\n"
"\n"
"USAGE: funcinterval [-h] [-p PID] [-i INTERVAL] [-T] [-m] [-v]\n"
"\n"
"Example:\n"
"   ./funcinterval do_sys_open            # time the interval of do_sys_open()\n"
"   ./funcinterval -m do_nanosleep        # time the interval of do_nanosleep(), in milliseconds\n"
"   ./funcinterval -mTi 5 vfs_read        # output every 5 seconds, with timestamps\n"
"   ./funcinterval -p 181 vfs_read        # time process 181 only\n"
"   ./funcinterval t:vmscan:mm_vmscan_direct_reclaim_begin     # time the interval of mm_vmscan_direct_reclaim_begin tracepoint\n"
"   ./funcinterval -p 181 -i 3 c:malloc             # time the interval of c:malloc used by process 181 every 3 seconds\n";

static struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "timestamp", 'T', NULL, 0, "include timestamp on output", 0 },
	{ "milliseconds", 'm', NULL, 0, "millisecond histogram", 0 },
	{ "pid", 'p', "PID", 0, "trace this PID only", 0 },
	{ "interval", 'i', "INTERVAL", 0, "summary interval, in seconds", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help", 0 },
	{}
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
		env.pid = argp_parse_long(key, arg, state);
		break;
	case 'm':
		env.milliseconds = true;
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case 'T':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num != 0) {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		env.functions = arg;
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

static int print_log2_hists(struct funcinterval_bpf *obj)
{
	const char *units = env.milliseconds ? "msecs" : "usecs";
	struct bpf_map *hists = obj->maps.hists;
	int err, fd = bpf_map__fd(hists);
	__u32 lookup_key = -1, next_key;
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	lookup_key = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	fd = bpf_map__fd(obj->maps.start);
	lookup_key = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup start : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

static int split_pattern(const char *raw_pattern, enum TRACE_TYPE *type,
			 const char **library, const char **pattern)
{
	const char *string1, *string2, *string3;
	char *raw_pattern_tmp = strdup(raw_pattern);

	string1 = strsep(&raw_pattern_tmp, ":");
	if (!raw_pattern_tmp) {
		/* Not found ':', return raw_pattern */
		*type = KPROBE;
		*pattern = raw_pattern;
		return 0;
	}

	string2 = strsep(&raw_pattern_tmp, ":");
	if (!raw_pattern_tmp) {
		/* One ':' found, return library */
		*type = UPROBE;
		*library = string1;
		*pattern = string2;
		return 0;
	}

	string3 = strsep(&raw_pattern_tmp, ":");
	if (strlen(string1) != 1)
		return -EINVAL;
	else if (string1[0] == 't')
		*type = TRACEPOINT;
	else if (string1[0] == 'p') {
		if (strlen(string2) == 0)
			*type = KPROBE;
		else
			*type = UPROBE;
	} else
		return -EINVAL;

	if (*type != KPROBE)
		*library = string2;
	*pattern = string3;

	return 0;
}


static int attach_uprobe(struct funcinterval_bpf *obj, const char *binary,
			 const char *function)
{
	int pid = env.pid;
	char bin_path[PATH_MAX];
	off_t func_off;

	if (pid == 0)
		pid = getpid();

	if (resolve_binary_path(binary, pid, bin_path, sizeof(bin_path)))
		return 1;

	func_off = get_elf_func_offset(bin_path, function);
	if (func_off < 0) {
		warning("Could not find %s in %s\n", function, bin_path);
		return 1;
	}

	obj->links.function_uprobe_entry =
		bpf_program__attach_uprobe(obj->progs.function_uprobe_entry,
					   false, pid ?: -1, bin_path, func_off);
	if (!obj->links.function_uprobe_entry) {
		warning("Failed to attach uprobe: %d\n", -errno);
		return 1;
	}

	return 0;
}

static int attach_tracepoint(struct funcinterval_bpf *obj, const char *library,
			     const char *pattern)
{
	obj->links.tracepoint_entry =
		bpf_program__attach_tracepoint(obj->progs.tracepoint_entry,
					       library, pattern);
	if (!obj->links.tracepoint_entry) {
		warning("Failed to attach t:%s:%s\n", library, pattern);
		return -errno;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct funcinterval_bpf *obj;
	int err;
	enum TRACE_TYPE type = 1;
	const char *library, *pattern;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = funcinterval_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_pid = env.pid;
	obj->rodata->targ_ms = env.milliseconds;

	split_pattern(env.functions, &type, &library, &pattern);

	switch (type) {
	case UPROBE:
		bpf_program__set_autoload(obj->progs.function_entry, false);
		bpf_program__set_autoload(obj->progs.tracepoint_entry, false);
		break;
	case KPROBE:
		bpf_program__set_autoload(obj->progs.tracepoint_entry, false);
		bpf_program__set_autoload(obj->progs.function_uprobe_entry, false);
		break;
	case TRACEPOINT:
		bpf_program__set_autoload(obj->progs.function_entry, false);
		bpf_program__set_autoload(obj->progs.function_uprobe_entry, false);
		break;
	default:
		warning("Wrong trace type, exiting\n");
		goto cleanup;
	}

	err = funcinterval_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	switch (type) {
	case KPROBE:
		obj->links.function_entry = bpf_program__attach_kprobe(obj->progs.function_entry,
								       false,
								       pattern);
		if (!obj->links.function_entry) {
			warning("Failed to attach BPF programs\n");
			goto cleanup;
		}
		break;
	case TRACEPOINT:
		err = attach_tracepoint(obj, library, pattern);
		if (err) {
			warning("Failed to attach BPF programs\n");
			goto cleanup;
		}
		break;
	case UPROBE:
		err = attach_uprobe(obj, library, pattern);
		if (err) {
			warning("Failed to attach BPF programs\n");
			goto cleanup;
		}
		break;
	default:
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		err = 1;
		warning("Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Tracing %s for \"%s\"... Hit Ctrl-C to end.\n", attach_type[type], pattern);

	while (!exiting) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			char ts[32];

			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s\n", ts);
		}

		err = print_log2_hists(obj);
		if (err)
			break;
	}

cleanup:
	funcinterval_bpf__destroy(obj);

	return err != 0;
}

