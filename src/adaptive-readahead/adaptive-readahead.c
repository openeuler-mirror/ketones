// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "adaptive-readahead.h"
#include "adaptive-readahead.skel.h"
#include "compat.h"
#include "trace_helpers.h"
#include <sys/stat.h>

static volatile sig_atomic_t exiting;

static struct env {
	bool verbose;
	char *disk;
} env;

const char *argp_program_version = "adaptive-readahead 0.1";
const char *argp_program_bug_address = "Youling Tang <tangyouling@kylinos.cn>";
const char argp_program_doc[] =
"Adaptive adjustment of read ahead size.\n"
"\n"
"USAGE: adaptive-readahead [-d disk]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "disk", 'd', "DISK", 0, "Specified disk", 0 },
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
	case 'd':
		env.disk = arg;
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

static void reset_read_ahead_kb(int fd, char *ahead_kb)
{
	if (fd <= 0)
		return;

	write(fd, ahead_kb, strlen(ahead_kb));
	printf("Reset the read_ahead_kb value to %s\n", ahead_kb);
}

static void set_read_ahead_kb(int fd, char *value)
{
	char buf[10] = {};

	lseek(fd, 0, SEEK_SET);
	read(fd, buf, sizeof(buf));

	if (!strncmp(buf, value, strlen(value)))
		return;

	write(fd, value, strlen(value));
	printf("Adjust the read_ahead_kb value to %s\n", value);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	int fd = *(int *)ctx;

	if (fd <= 0)
		printf("readahead fd error\n");

	if (e->mode)
		set_read_ahead_kb(fd, "4096");
	else
		set_read_ahead_kb(fd, "128");

	fflush(stdout);
	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu event on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct adaptive_readahead_bpf *obj;
	struct bpf_buffer *buf = NULL;
	char path[100] = {};
	char ahead_kb[10] = {};
	int err, fd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	if (!env.disk) {
		warning("Please use -d to specify the disk\n");
		return 1;
	}

	sprintf(path, "/sys/class/block/%s/queue/read_ahead_kb", env.disk);
	fd = open(path, O_RDWR);
	if (!fd) {
		err = -errno;
		return err;
	}

	read(fd, ahead_kb, sizeof(ahead_kb));
	printf("The current system read_ahead_kb is %s\n", ahead_kb);

	obj = adaptive_readahead_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		close(fd);
		return 1;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/*
	 * starting from v5.10-rc1, __do_page_cache_readahead has renamed to
	 * do_page_cache_ra, so we specify the function dynamically.
	 */
	if (!kprobe_exists("page_cache_ra_unbounded"))
		bpf_program__set_autoload(obj->progs.kprobe_page_cache_ra_unbounded, false);
	else
		bpf_program__set_autoload(obj->progs.kprobe__do_page_cache_readahead, false);

	err = adaptive_readahead_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = adaptive_readahead_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, &fd);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	warning("Jump to looping\n");
	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %d\n", err);
			break;
		}
		/* reset err to 0 when exiting */
		err = 0;
	}

cleanup:
	reset_read_ahead_kb(fd, ahead_kb);
	bpf_buffer__free(buf);
	adaptive_readahead_bpf__destroy(obj);

	if (fd > 0)
		close(fd);

	return err != 0;
}
