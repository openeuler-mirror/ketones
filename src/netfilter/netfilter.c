// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Rongguang Wei <weirongguang@kylinos.cn>

#include "commons.h"
#include "netfilter.h"
#include "netfilter.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "compat.h"
#include <arpa/inet.h>
#include <linux/netfilter.h>

static volatile sig_atomic_t exiting;

struct ksyms *ksyms;

const char *argp_program_version = "netfilter 0.1";
const char *argp_program_bug_address = "Rongguang Wei <weirongguang@kylinos.cn>";
const char argp_program_doc[] =
"\nnetfilter: Trace Netfilter hook by the kernel\n"
"\n"
"EXAMPLES:\n"
"    netfilter                # trace the netfilter chain which cause drop\n"
"    netfilter -l             # list the kernel netfilter hook function\n"
"    netfilter -m             # show the hook function which cause drop\n"
"    netfilter -t  10         # show the time what the hook function used\n"
"                             # more than 10us\n"
;

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "help", 'h', NULL, 0, "Show this help message and exit", 0 },
	{ "list", 'l', NULL, 0, "List the hook function", 0 },
	{ "monitor", 'm', NULL, 0, "Monitor the hook function drop", 0},
	{ "time", 't', "TIME", 0, "Eable and show the hook function time which used more than time", 0},
	{}
};

static struct env {
	bool verbose;
	bool list;
	bool monitor;
	int time;
	bool used_time;
} env;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'm':
		env.monitor = true;
		break;
	case 'l':
		env.list = true;
		break;
	case 't':
		env.used_time = true;
		env.time = argp_parse_long(key, arg, state);
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

static void pausing(void)
{
	while (!exiting)
		pause();
}

static void kprobe_hook_check(struct netfilter_bpf *obj)
{
	if (!is_kernel_module("nf_defrag_ipv4")) {
		bpf_program__set_autoload(obj->progs.ipv4_conntrack_defrag_kprobe, false);
		bpf_program__set_autoload(obj->progs.ipv4_conntrack_defrag_ret_kprobe, false);
	}

	if (!is_kernel_module("iptable_raw")) {
		bpf_program__set_autoload(obj->progs.iptable_raw_hook_kprobe, false);
		bpf_program__set_autoload(obj->progs.iptable_raw_hook_ret_kprobe, false);
	}

	if (!is_kernel_module("nf_conntrack")) {
		bpf_program__set_autoload(obj->progs.ipv4_conntrack_in_kprobe, false);
		bpf_program__set_autoload(obj->progs.ipv4_conntrack_in_ret_kprobe, false);
	}

	if (!is_kernel_module("iptable_mangle")) {
		bpf_program__set_autoload(obj->progs.iptable_mangle_hook_kprobe, false);
		bpf_program__set_autoload(obj->progs.iptable_mangle_hook_ret_kprobe, false);
	}

	if (!is_kernel_module("nf_nat")) {
		bpf_program__set_autoload(obj->progs.nf_nat_ipv4_in_kprobe, false);
		bpf_program__set_autoload(obj->progs.nf_nat_ipv4_in_ret_kprobe, false);
		bpf_program__set_autoload(obj->progs.nf_nat_ipv4_fn_kprobe, false);
		bpf_program__set_autoload(obj->progs.nf_nat_ipv4_fn_ret_kprobe, false);
		bpf_program__set_autoload(obj->progs.nf_nat_ipv4_local_fn_kprobe, false);
		bpf_program__set_autoload(obj->progs.nf_nat_ipv4_local_fn_ret_kprobe, false);
		bpf_program__set_autoload(obj->progs.nf_nat_ipv4_out_kprobe, false);
		bpf_program__set_autoload(obj->progs.nf_nat_ipv4_out_ret_kprobe, false);
	}

	if (!is_kernel_module("iptable_filter")) {
		bpf_program__set_autoload(obj->progs.iptable_filter_hook_kprobe, false);
		bpf_program__set_autoload(obj->progs.iptable_filter_hook_ret_kprobe, false);
	}

	if (!is_kernel_module("iptable_security")) {
		bpf_program__set_autoload(obj->progs.iptable_security_hook_kprobe, false);
		bpf_program__set_autoload(obj->progs.iptable_security_hook_ret_kprobe, false);
	}

	if (!is_kernel_module("nf_conntrack")) {
		bpf_program__set_autoload(obj->progs.ipv4_confirm_kprobe, false);
		bpf_program__set_autoload(obj->progs.ipv4_confirm_ret_kprobe, false);
		bpf_program__set_autoload(obj->progs.ipv4_conntrack_local_kprobe, false);
		bpf_program__set_autoload(obj->progs.ipv4_conntrack_local_ret_kprobe, false);
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event_data *event = data;
	const struct ksym *ksym;
	struct hook_function hook_func = {};
	struct hook_data hook_data;
	int map_fd = *(int *)ctx;
	int err;

	if (env.used_time) {
		if (event->times > env.time)
			printf("Chain: %-22s return: %-10s times: %lldus\n",
				nf_inet_hooks[event->hooknum],
				nf_inet_result[event->result],
				event->times);
		return 0;
	}

	if (event->result)
		return 0;

	printf("Chain: %-22s return: %-10s\n", nf_inet_hooks[event->hooknum],
					       nf_inet_result[event->result]);

	if (env.monitor) {
		hook_func.hooknum = event->hooknum;
		hook_func.hookfn = event->hookfn;

		err = bpf_map_lookup_elem(map_fd, &hook_func, &hook_data);
		if (err < 0) {
			warning("bpf_map_lookup_elem failed: %s\n",
				strerror(errno));
			return 0;
		}

		printf("\t%20s %-30s %-10s\n", " ", "HOOKS", "RESULT");
		ksym = ksyms__map_addr(ksyms, hook_func.hookfn);
		if (ksym)
			printf("\t[<%016llx>] %-30s %-10s\n",
			       hook_func.hookfn,
			       ksym->name,
			       nf_inet_result[hook_data.result]);
	}

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static int trace_event(struct bpf_buffer *buf, int map_fd)
{
	int err;

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, &map_fd);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		return err;
	}

	while (!exiting) {
		err = bpf_buffer__poll(buf, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %s\n",
				strerror(-err));
			break;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

	return err;
}

static void print_event(int map_fd)
{
	const struct ksym *ksym;
	struct hook_data hook_data;
	struct hook_function index_key;
	struct hook_function prev_key = {};
	__u64 nf_chain[NF_INET_NUMHOOKS][MAX_HOOKS] = {0,};
	int err;

	while (!bpf_map_get_next_key(map_fd, &prev_key, &index_key)) {
		err = bpf_map_lookup_elem(map_fd, &index_key, &hook_data);
		if (err < 0) {
			warning("bpf_map_lookup_elem failed: %s\n",
				strerror(errno));
			break;
		}

		nf_chain[index_key.hooknum][hook_data.index] = index_key.hookfn;
		prev_key = index_key;
	}

	for (int i = 0; i < NF_INET_NUMHOOKS; i++) {
		printf("\nChain: %-22s\n", nf_inet_hooks[i]);
		printf("\t%20s %-30s\n", " ", "HOOKS");
		for (int j = 0; j < MAX_HOOKS; j++) {
			if (!nf_chain[i][j])
				break;
			ksym = ksyms__map_addr(ksyms, nf_chain[i][j]);
			if (ksym)
				printf("\t[<%016llx>] %-30s\n", nf_chain[i][j],
								ksym->name);
		}
	}
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	DEFINE_SKEL_OBJECT(obj);
	struct bpf_buffer *buf = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n",
			strerror(-err));
		return -1;
	}

	obj = SKEL_OPEN_OPTS(&open_opts);
	if (!obj) {
		warning("Failed to open BPF objects\n");
		err = 1;
		goto cleanup;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		warning("Failed to create ring/perf buffer\n");
		err = -errno;
		goto cleanup;
	}

	if (fentry_can_attach("nf_hook_slow", NULL)) {
		bpf_program__set_autoload(obj->progs.nf_hook_slow_kprobe,
					  false);
		bpf_program__set_autoload(obj->progs.nf_hook_slow_ret_kprobe,
					  false);
	} else {
		bpf_program__set_autoload(obj->progs.nf_hook_slow, false);
		bpf_program__set_autoload(obj->progs.nf_hook_slow_ret, false);
	}

	if (env.list) {
		bpf_program__set_autoload(obj->progs.nf_hook_slow_ret_kprobe,
					  false);
		bpf_program__set_autoload(obj->progs.nf_hook_slow_ret, false);
	}

	kprobe_hook_check(obj);

	err = SKEL_LOAD(obj);
	if (err) {
		warning("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = SKEL_ATTACH(obj);
	if (err) {
		warning("Failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("Failed to load ksyms\n");
		err = -ENOMEM;
		goto cleanup;
	}

	printf("Tracing Netfilter hook ... Hit Ctrl-C to end\n");

	if (env.list) {
		pausing();
		print_event(bpf_map__fd(obj->maps.hooks_data));
	} else {
		trace_event(buf, bpf_map__fd(obj->maps.hooks_data));
	}

cleanup:
	SKEL_DESTROY(obj);
	cleanup_core_btf(&open_opts);
	ksyms__free(ksyms);

	return err != 0;
}
