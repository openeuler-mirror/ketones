// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "bashreadline.h"
#include "bashreadline.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

static volatile sig_atomic_t exiting;

const char *argp_program_version = "bashreadline 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Print entered bash commands from all running shells.\n"
"\n"
"USAGE: bashreadline [-s <path/to/libreadline.so>]\n"
"\n"
"EXAMPLES:\n"
"    bashreadline\n"
"    bashreadline -s /usr/lib/libreadline.so\n";

static const struct argp_option opts[] = {
	{ "shared", 's', "PATH", 0, "the location of libreadline.so library" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static struct env {
	char *libreadline_path;
	bool verbose;
} env = {};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 's':
		if (!arg)
			return ARGP_ERR_UNKNOWN;
		env.libreadline_path = strdup(arg);
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

static void handle_event(void *ctx, int cpu, void *data, __u32 data_size)
{
	readline_str_t *e = data;
	char ts[16];

	strftime_now(ts, sizeof(ts), "%H:%M:%S");

	printf("%-9s %-7d %s\n", ts, e->pid, e->str);
}

static void handle_lost_event(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void sig_handler(int sig)
{
	exiting = 1;
}

static char *find_readline_function_name(const char *bash_path)
{
	bool found = false;
	int fd = -1;
	Elf *elf = NULL;
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;

	elf = open_elf(bash_path, &fd);
	while ((scn = elf_nextscn(elf, scn)) != NULL && !found) {
		gelf_getshdr(scn, &shdr);
		if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
			Elf_Data *data = elf_getdata(scn, NULL);

			if (data != NULL) {
				GElf_Sym *symtab = (GElf_Sym *) data->d_buf;
				int sym_count = shdr.sh_size / shdr.sh_entsize;

				for (int i = 0; i < sym_count; ++i) {
					if (strcmp("readline_internal_teardown",
						   elf_strptr(elf,
							      shdr.sh_link,
							      symtab[i].st_name)) == 0) {
						found = true;
						break;
					}
				}
			}
		}
	}

	close_elf(elf,fd);
	if (found)
		return "readline_internal_teardown";
	else
		return "readline";
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	struct bashreadline_bpf *obj;
	struct perf_buffer *pb = NULL;
	char *readline_so_path;
	off_t func_off;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	if (env.libreadline_path) {
		readline_so_path = env.libreadline_path;
	} else {
		const char *bash_path = "/bin/bash";

		if (get_elf_func_offset(bash_path, find_readline_function_name(bash_path)) >= 0)
			readline_so_path = strdup(bash_path);
		else {
			readline_so_path = find_library_so(bash_path, "/libreadline.so");
			if (!readline_so_path) {
				warning("Failed to find readline\n");
				return 1;
			}
		}
	}

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		goto cleanup;
	}

	obj = bashreadline_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	err = bashreadline_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		goto cleanup;
	}

	func_off = get_elf_func_offset(readline_so_path, find_readline_function_name(readline_so_path));
	if (func_off < 0) {
		warning("Count not find readline in %s\n", readline_so_path);
		goto cleanup;
	}

	obj->links.printret = bpf_program__attach_uprobe(obj->progs.printret, true, -1,
							 readline_so_path, func_off);
	if (!obj->links.printret) {
		err = -errno;
		warning("Failed to attach readline: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_event, NULL, NULL);
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

	printf("%-9s %-7s %s\n", "TIME", "PID", "COMMAND");
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	if (readline_so_path)
		free(readline_so_path);
	perf_buffer__free(pb);
	bashreadline_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
