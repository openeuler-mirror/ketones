// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on virtiostat.py - zhenwei pi

#include "commons.h"
#include "virtiostat.h"
#include "virtiostat.skel.h"
#include "compat.h"
#include "btf_helpers.h"

static volatile sig_atomic_t exiting;

static struct env {
	bool verbose;
	bool is_filter_devname;
	bool is_filter_driver;
	int interval;
	char *filter_devname;
	char *filter_driver;
} env = {
	.interval		= 3,
};

const char *argp_program_version = "virtiostat 0.1";
const char *argp_program_bug_address = "Yang Feng <yangfeng@kylinos.cn>";
const char argp_program_doc[] =
"virtiostat: Show virtio devices input/output statistics.\n"
"\n"
"USAGE: virtiostat [-v] [-h] [-d DRIVER] [-n DEVNAME] [-i INTERVAL]\n"
"\n"
"Example:\n"
"    virtiostat                 # print 3(default) second summaries\n"
"    virtiostat -i 1            # 1 second summaries\n"
"    virtiostat -n virtio0      # only show virtio0 device\n"
"    virtiostat -d virtio_net   # only show virtio net devices\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "driver", 'd', "DRIVER", 0, "filter for driver name", 0 },
	{ "devname", 'n', "DEVNAME", 0, "filter for device name", 0 },
	{ "interval", 'i', "INTERVAL", 0, "output interval, in seconds", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'd':
		env.filter_driver = arg;
		env.is_filter_driver = true;
		break;
	case 'n':
		env.filter_devname = arg;
		env.is_filter_devname = true;
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

static int print_data(struct virtiostat_bpf *obj)
{
	__u64 lookup_key = -1, next_key;
	virtio_stat_t stats;
	char time[16];
	int fd = bpf_map__fd(obj->maps.stats);
	int err;

	printf("%-8s\n", strftime_now(time, sizeof(time), "%H:%M:%S"));
	printf("%14s %8s %10s %7s %7s %14s %14s\n",
		"Driver", "Device", "VQ Name", "In SGs", "Out SGs", "In BW", "Out BW");

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		lookup_key = next_key;
		err = bpf_map_lookup_elem(fd, &next_key, &stats);
		if (err < 0) {
			warning("Failed to lookup infos: %d\n", err);
			return err;
		}
		printf("%14s %8s %10s %7d %7d %14lld %14lld\n",
			stats.driver, stats.dev, stats.vqname, stats.in_sgs,
			stats.out_sgs, stats.in_bw, stats.out_bw);
	}

	/* Clear the map */
	lookup_key = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		int err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			warning("Failed to cleanup info: %d\n", err);
			return err;
		}
		lookup_key = next_key;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct virtiostat_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	obj = virtiostat_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	if (env.is_filter_devname) {
		obj->rodata->is_filter_devname = env.is_filter_devname;
		strncpy(obj->rodata->filter_devname, env.filter_devname, CMPMAX - 1);
		obj->rodata->filter_devname[CMPMAX - 1] = '\0';
	}
	if (env.is_filter_driver) {
		obj->rodata->is_filter_driver = env.is_filter_driver;
		strncpy(obj->rodata->filter_driver, env.filter_driver, CMPMAX - 1);
		obj->rodata->filter_driver[CMPMAX - 1] = '\0';
	}

	err = virtiostat_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = virtiostat_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing virtio devices statistics ... Hit Ctrl-C to end.\n");

	while (!exiting) {
		sleep(env.interval);
		if (print_data(obj))
			break;
	}

cleanup:
	virtiostat_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
