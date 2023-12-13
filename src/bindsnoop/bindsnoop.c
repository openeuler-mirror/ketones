// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "bindsnoop.h"
#include "bindsnoop.skel.h"
#include "trace_helpers.h"
#include "btf_helpers.h"

#include <sys/socket.h>
#include <arpa/inet.h>

static struct env {
	char	*cgroupspath;
	bool	cg;
	bool	emit_timestamp;
	pid_t	target_pid;
	bool	ignore_errors;
	char	*target_ports;
	bool	verbose;
} env = {
	.ignore_errors = true,
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "bindsnoop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Trace bind syscalls.\n"
"\n"
"USAGE: bindsnoop [-h] [-t] [-x] [-p PID] [-P ports] [-c CG]\n"
"\n"
"EXAMPLES:\n"
"    bindsnoop             # trace all bind syscall\n"
"    bindsnoop -t          # include timestamps\n"
"    bindsnoop -x          # include errors on output\n"
"    bindsnoop -p 1216     # only trace PID 1216\n"
"    bindsnoop -c CG       # Trace process under cgroupsPath CG\n"
"    bindsnoop -P 80,81    # only trace port 80 and 81\n"
"\n"
"Socket options are reported as:\n"
"  SOL_IP     IP_FREEBIND              F....\n"
"  SOL_IP     IP_TRANSPARENT           .T...\n"
"  SOL_IP     IP_BIND_ADDRESS_NO_PORT  ..N..\n"
"  SOL_SOCKET SO_REUSEADDR             ...R.\n"
"  SOL_SOCKET SO_REUSEPORT             ....r\n";

static const struct argp_option opts[] = {
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path" },
	{ "failed", 'x', NULL, 0, "Include errors on outputs" },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "ports", 'P', "PORTS", 0, "Comma-separated list of ports to trace" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	char *port;

	switch (key) {
	case 'p':
		env.target_pid = argp_parse_pid(key, arg, state);
		break;
	case 'c':
		env.cgroupspath = arg;
		env.cg = true;
		break;
	case 'P':
		if (!arg) {
			warning("No ports specified\n");
			argp_usage(state);
		}
		env.target_ports = strdup(arg);
		port = strtok(arg, ",");
		while (port) {
			int port_num = strtol(port, NULL, 10);
			if (errno || port_num <= 0 || port_num > 65536) {
				warning("Invalid ports: %s\n", arg);
				argp_usage(state);
			}
			port = strtok(NULL, ",");
		}
		break;
	case 'x':
		env.ignore_errors = false;
		break;
	case 't':
		env.emit_timestamp = true;
		break;
	case 'v':
		env.verbose = true;
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
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct bind_event *e = data;
	char addr[48];
	char opts[] = { 'F', 'T', 'N', 'R', 'r', '\0' };
	const char *proto;
	int i = 0;

	if (env.emit_timestamp) {
		char ts[32];

		strftime_now(ts, sizeof(ts), "%H:%M:%S");
		printf("%8s ", ts);
	}

	if (e->proto == IPPROTO_TCP)
		proto = "TCP";
	else if (e->proto == IPPROTO_UDP)
		proto = "UDP";
	else
		proto = "UNK";

	while (opts[i]) {
		if (!((1 << i) & e->opts)) {
			opts[i] = '.';
		}
		i++;
	}

	if (e->ver == 4)
		inet_ntop(AF_INET, e->addr, addr, sizeof(addr));
	else
		inet_ntop(AF_INET6, e->addr, addr, sizeof(addr));

	printf("%-7d %-16s %-3d %-5s %-5s %-4d %-5d %-48s\n",
	       e->pid, e->task, e->ret, proto, opts, e->bound_dev_if, e->port, addr);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct bindsnoop_bpf *obj;
	int err;
	int cgfd = -1;

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

	obj = bindsnoop_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->filter_memcg = env.cg;
	obj->rodata->target_pid = env.target_pid;
	obj->rodata->ignore_errors = env.ignore_errors;
	obj->rodata->filter_by_port = env.target_ports != NULL;

	err = bindsnoop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	/* update cgroup path fd to map */
	if (env.cg) {
		int idx = 0;
		int cg_map_fd = bpf_map__fd(obj->maps.cgroup_map);

		cgfd = open(env.cgroupspath, O_RDONLY);
		if (cgfd < 0) {
			warning("Failed opening Cgroup path: %s", env.cgroupspath);
			goto cleanup;
		}

		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY)) {
			warning("Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	if (env.target_ports) {
		int port_map_fd = bpf_map__fd(obj->maps.ports);
		char *port = strtok(env.target_ports, ",");

		while (port) {
			int port_num = strtol(port, NULL, 10);

			bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
			port = strtok(NULL, ",");
		}
	}

	err = bindsnoop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		warning("Failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (env.emit_timestamp)
		printf("%-8s ", "TIME(s)");
	printf("%-7s %-16s %-3s %-5s %-5s %-4s %-5s %-48s\n",
	       "PID", "COMM", "RET", "PROTO", "OPTS", "IF", "PORT", "ADDR");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}

		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	bindsnoop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}
