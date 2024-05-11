// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "readahead.h"
#include "readahead.skel.h"
#include "trace_helpers.h"

static struct env {
	int duration;
	bool verbose;
} env = {
	.duration = -1
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "readahead 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Show fs automatic read-ahead usage.\n"
"\n"
"USAGE: readahead [--help] [-d DURATION]\n"
"\n"
"EXAMPLES:\n"
"    readahead              # summarize on-CPU time as a histogram\n"
"    readahead -d 10        # trace for 10 seconds only\n";

static const struct argp_option opts[] = {
	{ "duration", 'd', "DURATION", 0, "Duration to trace", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose output debug", 0 },
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
		env.duration = argp_parse_long(key, arg, state);
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

static bool readahead__set_attach_target(struct bpf_program *prog)
{
	if (!bpf_program__set_attach_target(prog, 0, "do_page_cache_ra"))
		return true;

	if (!bpf_program__set_attach_target(prog, 0,
					    "__do_page_cache_readahead"))
		return true;

	return false;
}

static void disable_kprobes(struct readahead_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.do_page_cache_ra_kprobe, false);
	bpf_program__set_autoload(obj->progs.do_page_cache_ra_kretprobe, false);
	bpf_program__set_autoload(obj->progs.page_cache_alloc_kretprobe, false);
	bpf_program__set_autoload(obj->progs.mark_page_accessed_kprobe, false);
	bpf_program__set_autoload(obj->progs.filemap_alloc_folio_kretprobe, false);
	bpf_program__set_autoload(obj->progs.folio_mark_accessed_kprobe, false);
}

static void disable_fentry(struct readahead_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.do_page_cache_ra, false);
	bpf_program__set_autoload(obj->progs.do_page_cache_ra_ret, false);
	bpf_program__set_autoload(obj->progs.page_cache_alloc_ret, false);
	bpf_program__set_autoload(obj->progs.mark_page_accessed, false);
	bpf_program__set_autoload(obj->progs.filemap_alloc_folio_ret, false);
	bpf_program__set_autoload(obj->progs.folio_mark_accessed, false);
}

static bool try_fentry(struct readahead_bpf *obj)
{
	/*
	 * starting from v5.10-rc1, __do_page_cache_readahead has renamed to
	 * do_page_cache_ra, so we specify the function dynamically.
	 */
	if (!readahead__set_attach_target(obj->progs.do_page_cache_ra))
		goto out_shutdown_fentry;
	if (!readahead__set_attach_target(obj->progs.do_page_cache_ra_ret))
		goto out_shutdown_fentry;

	if (fentry_can_attach("folio_mark_accessed", NULL) &&
	    fentry_can_attach("filemap_alloc_folio", NULL)) {
		bpf_program__set_autoload(obj->progs.page_cache_alloc_ret, false);
		bpf_program__set_autoload(obj->progs.mark_page_accessed, false);
	} else if (fentry_can_attach("mark_page_accessed", NULL) &&
		   fentry_can_attach("__page_cache_alloc", NULL)) {
		bpf_program__set_autoload(obj->progs.filemap_alloc_folio_ret, false);
		bpf_program__set_autoload(obj->progs.folio_mark_accessed, false);
	} else {
		goto out_shutdown_fentry;
	}

	disable_kprobes(obj);
	return true;

out_shutdown_fentry:
	disable_fentry(obj);
	return false;
}

static int set_autoload_kprobes(struct readahead_bpf *obj)
{
	if (kprobe_exists("folio_mark_accessed") &&
	    kprobe_exists("filemap_alloc_folio")) {
		bpf_program__set_autoload(obj->progs.page_cache_alloc_kretprobe, false);
		bpf_program__set_autoload(obj->progs.mark_page_accessed_kprobe, false);
	} else if (kprobe_exists("mark_page_accessed") &&
		   kprobe_exists("__page_cache_alloc")) {
		bpf_program__set_autoload(obj->progs.filemap_alloc_folio_kretprobe, false);
		bpf_program__set_autoload(obj->progs.folio_mark_accessed_kprobe, false);
	} else {
		return 1;
	}

	return 0;
}

static int attach_kprobes(struct readahead_bpf *obj)
{
	/*
	 * starting from v5.10-rc1, __do_page_cache_readahead has renamed to
	 * do_page_cache_ra, so we specify the function dynamically.
	 */
	if (kprobe_exists("do_page_cache_ra")) {
		obj->links.do_page_cache_ra_kprobe =
			bpf_program__attach_kprobe(obj->progs.do_page_cache_ra_kprobe,
						   false,
						   "do_page_cache_ra");
		if (!obj->links.do_page_cache_ra_kprobe)
			return 1;
	} else {
		obj->links.do_page_cache_ra_kprobe =
			bpf_program__attach_kprobe(obj->progs.do_page_cache_ra_kprobe,
						   false,
						   "__do_page_cache_readahead");
		if (!obj->links.do_page_cache_ra_kprobe)
			return 1;
	}

	if (kprobe_exists("do_page_cache_ra")) {
		obj->links.do_page_cache_ra_kretprobe =
			bpf_program__attach_kprobe(obj->progs.do_page_cache_ra_kretprobe,
						   true,
						   "do_page_cache_ra");
		if (!obj->links.do_page_cache_ra_kretprobe)
			return 1;
	} else {
		obj->links.do_page_cache_ra_kretprobe =
			bpf_program__attach_kprobe(obj->progs.do_page_cache_ra_kretprobe,
						   true,
						   "__do_page_cache_readahead");
		if (!obj->links.do_page_cache_ra_kretprobe)
			return 1;
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
	struct readahead_bpf *obj;
	struct hist *histp;
	int err;
	bool support_fentry;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	obj = readahead_bpf__open();
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	support_fentry = try_fentry(obj);
	if (!support_fentry) {
		err = set_autoload_kprobes(obj);
		if (err)
			goto cleanup;
	}

	err = readahead_bpf__load(obj);
	if (err) {
		warning("failed to load BPF object\n");
		goto cleanup;
	}

	if (!obj->bss) {
		warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		goto cleanup;
	}

	err = support_fentry ? readahead_bpf__attach(obj) : attach_kprobes(obj);
	if (err) {
		warning("Failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing fs read-ahead ... Hit Ctrl-C tp end.\n");

	sleep(env.duration);
	printf("\n");

	histp = &obj->bss->hist;

	printf("Readahead unused/total pages: %d/%d\n",
	       histp->unused, histp->total);
	print_log2_hist(histp->slots, MAX_SLOTS, "msecs");

cleanup:
	readahead_bpf__destroy(obj);
	return err != 0;
}
