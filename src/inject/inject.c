// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "compat.h"
#include "inject.h"
#include "inject.skel.h"
#include <regex.h>
#include "btf_helpers.h"

static volatile sig_atomic_t exiting;

#define FRAM_BUF_LEN 128
#define SPEC_BUF_LEN 1024

struct frame_t {
	char func[FRAM_BUF_LEN];
	char pred[FRAM_BUF_LEN];
};

const char *error_injection_entry[MAX_MODE] = {
	[KMALLOC_MODE] = "should_failslab(struct kmem_cache *s, gfp_t gfpflags)",
	[BIO_MODE] = "should_fail_bio(struct bio *bio)",
	[ALLOC_PAGE_MODE] = "should_fail_alloc_page(gfp_t gfp_mask, unsigned int order)",
};

static struct env {
	enum inject_mode mode;
	__u32 probability;
	__u32 enable_flag;
	long max_err_count;
	char spec[SPEC_BUF_LEN];
	bool verbose;
	int f_cnt;
	struct frame_t frames[STACK_MAX_DEPTH];
} env = {
	.probability = 0xFFFFFF00,
	.max_err_count = -1,
	.enable_flag = 0xFFFFFFFF,
};

const char *argp_program_version = "inject 0.1";
const char *argp_program_bug_address = "Yuan Chen <chenyuan@kylinos.cn>";
const char argp_program_doc[] =
"Fail specified kernel functionality when call chain and predicates are met\n"
"\n"
"USAGE: inject [-h] [-I header] [-P probability] [-v] [-c COUNT] {kmalloc,bio,alloc_page} spec\n"
"\n"
"positional arguments:\n"
"{kmalloc,bio,alloc_page}  indicate which base kernel function to fail\n"
"spec                      specify call chain\n"
"examples:\n"
"inject kmalloc -v 'SyS_mount()'                      # Fails all calls to syscall mount\n"
"inject kmalloc -v '(true) => SyS_mount()(true)'      # Explicit rewriting of above\n"
"inject kmalloc -v 'mount_subtree() => btrfs_mount()' # Fails btrfs mounts only\n"
"inject kmalloc -v -P 0.01 'SyS_mount()'             # Fails calls to syscall mount with 1% probability\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "verbose mode: print the BPF program (for debugging purposes)" },
	{ "spec", 1, "SPEC", 0, "specify call chain" },
	{ "probability", 'P', "NUM", 0, "probability that this call chain will fail" },
	{ "count", 'c', "NUM", 0, "Number of fails before bypassing the override" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	float p;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 1:
		strncpy(env.spec, arg, sizeof(env.spec));
		break;
	case 'P':
		p = argp_parse_float(key, arg, state);
		if (p > 1.0)
			p = 1.0;
		env.probability = (__u32)(0xFFFFFF00 * p);
		break;
	case 'c':
		env.max_err_count = argp_parse_long(key, arg, state);
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0) {
			if (!strcmp("kmalloc", arg))
				env.mode = KMALLOC_MODE;
			else if (!strcmp("bio", arg))
				env.mode = BIO_MODE;
			else if (!strcmp("alloc_page", arg))
				env.mode = ALLOC_PAGE_MODE;
			else {
				warning("Unrecognized inject mode: %s, {kmalloc, bio, alloc_page}", arg);
				argp_usage(state);
			}
		} else if (state->arg_num == 1) {
			if (env.spec[0] != '\0') {
				warning("Error inject spec: %s, please check spec set\n", arg);
				argp_usage(state);
			}
			strncpy(env.spec, arg, sizeof(env.spec));
		} else {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int parse_frames(void)
{
	int spec_len, i = 0;
	char *spec = env.spec;
	int count = 0, start = 0;
	char c;
	char cur_frame[2][FRAM_BUF_LEN] = {};
	int last_frame_added = 0;

	spec_len = strlen(spec);
	while (i <= spec_len) {
		if (count < 0) {
			warning("Check your parentheses\n");
			return -1;
		}

		c = spec[i];
		count += c == '(';
		count -= c == ')';
		if (count) {
			i++;
			continue;
		}

		if (c == '\0' || (c == '=' && spec[i + 1] == '>')) {
			// This block is closing a chunk. This means cur_frame must
			// have something in it.
			if (cur_frame[0][0] == '\0') {
				warning("Cannot parse spec, missing parens\n");
				return -1;
			}

			if (cur_frame[0][0] != '\0' && cur_frame[1][0] != '\0') {
				strncpy(env.frames[env.f_cnt].func, cur_frame[0], FRAM_BUF_LEN);
				strncpy(env.frames[env.f_cnt++].pred, cur_frame[1], FRAM_BUF_LEN);
			} else if (cur_frame[0][0] == '(') {
				strncpy(env.frames[env.f_cnt].func, error_injection_entry[env.mode],
					FRAM_BUF_LEN);
				strncpy(env.frames[env.f_cnt++].pred, cur_frame[0], FRAM_BUF_LEN);
			} else {
				strncpy(env.frames[env.f_cnt].func, cur_frame[0], FRAM_BUF_LEN);
				strncpy(env.frames[env.f_cnt++].pred, "(true)", FRAM_BUF_LEN);
			}

			memset(cur_frame[0], '\0', FRAM_BUF_LEN);
			memset(cur_frame[1], '\0', FRAM_BUF_LEN);
			i++;
			start = i + 1;
		} else if (c == ')') {
			while(isspace(spec[start]))
				start++;
			if (cur_frame[0][0] == '\0')
				memcpy(cur_frame[0], &spec[start], i - start + 1);
			else if (cur_frame[1][0] == '\0')
				memcpy(cur_frame[1], &spec[start], i - start + 1);
			else {
				warning("Check your parentheses\n");
				return -1;
			}
			start = i + 1;
			last_frame_added = start;
		}
		i++;
	}

	while(isspace(spec[last_frame_added]))
		last_frame_added++;

	if (last_frame_added != spec_len) {
		warning("Invalid characters found after last frame\n");
		return -1;
	}

	if (count) {
		warning("Check your parentheses\n");
		return -1;
	}

	if (strcmp(env.frames[0].func, error_injection_entry[env.mode])) {
		if (env.f_cnt + 1 > STACK_MAX_DEPTH) {
			warning("Check your parentheses\n");
			return -1;
		}
		for (i = env.f_cnt; i > 0; i--) {
			memcpy(env.frames[i].func, env.frames[i - 1].func, FRAM_BUF_LEN);
			memcpy(env.frames[i].pred, env.frames[i - 1].pred, FRAM_BUF_LEN);
		}
		strncpy(env.frames[0].func, error_injection_entry[env.mode], FRAM_BUF_LEN);
		strncpy(env.frames[0].pred, "(true)", FRAM_BUF_LEN);

		env.f_cnt++;
	}

	return 0;
}

static bool validate_predicate(const char *pred)
{
	char *str = strdup(pred);
	int len, i;
	int open = 1;
	bool ret = false;

	if (!str)
		return false;

	len = strlen(str);
	if (len > 0 && str[0] == '(') {
		for (i = 0; i < len; i++) {
			if (str[i] == '(')
				open++;
			else if (str[i] == ')')
				open--;
		}
		if (open != 0)
			goto cleanup;
	}
	ret = true;
cleanup:
	free(str);
	return ret;
}

static bool validate_identifier(const char *func)
{
	regex_t oregex;
	bool ret = false;
	char *str = strdup(func);
	char *tmp = strchr(str, '(');

	if (!tmp)
		return ret;

	tmp[0] = '\0';
	if (regcomp(&oregex, "[_a-zA-z][_a-zA-Z0-9]*$", REG_EXTENDED | REG_NOSUB) != 0) {
		warning("regcomp failed\n");
		return ret;
	}

	if (regexec(&oregex, str, 0, NULL, 0))
		goto cleanup;

	ret = true;
cleanup:
	if (str)
		free(str);
	regfree(&oregex);
	return ret;
}

static int parse_spec(void)
{
	int i;

	if (parse_frames())
		return -1;

	for (i = 0; i < env.f_cnt; i++) {
		printf("func: %s, pred: %s\n", env.frames[i].func, env.frames[i].pred);

		if (!validate_identifier(env.frames[i].func)) {
			warning("Invalid function identifier, %s\n", env.frames[i].func);
			return -1;
		}

		if (validate_predicate(env.frames[i].pred)) {
			warning("Invalid predicate, %s\n", env.frames[i].pred);
			return -1;
		}

		if (!strcmp(env.frames[i].pred, "(false)")) {
			env.enable_flag &= ~(1 << (i));
		}
	}

	return 0;
}

static int call_chain_entry_attach(struct inject_bpf *obj)
{
	struct bpf_link *link = NULL;
	struct bpf_program *entry_progs[STACK_MAX_DEPTH - 1];
	struct bpf_program *exit_progs[STACK_MAX_DEPTH - 1];
	int i, err = -1;
	char *str = NULL;

	entry_progs[0] = obj->progs.call_depth_entry_1;
	entry_progs[1] = obj->progs.call_depth_entry_2;
	entry_progs[2] = obj->progs.call_depth_entry_3;
	entry_progs[3] = obj->progs.call_depth_entry_4;
	entry_progs[4] = obj->progs.call_depth_entry_5;
	entry_progs[5] = obj->progs.call_depth_entry_6;
	entry_progs[6] = obj->progs.call_depth_entry_7;
	entry_progs[7] = obj->progs.call_depth_entry_8;

	exit_progs[0] = obj->progs.call_depth_exit_1;
	exit_progs[1] = obj->progs.call_depth_exit_2;
	exit_progs[2] = obj->progs.call_depth_exit_3;
	exit_progs[3] = obj->progs.call_depth_exit_4;
	exit_progs[4] = obj->progs.call_depth_exit_5;
	exit_progs[5] = obj->progs.call_depth_exit_6;
	exit_progs[6] = obj->progs.call_depth_exit_7;
	exit_progs[7] = obj->progs.call_depth_exit_8;

	for (i = 0; i < env.f_cnt - 1; i++) {
		str = strdup(env.frames[i + 1].func);
		char *chrp = strchr(str, '(');
		chrp[0] = '\0';
		link = bpf_program__attach_kprobe(entry_progs[i], false, str);
		if (!link) {
			warning("attach call_chain_entry_attach kprobe attach failed\n");
			goto cleanup;
		}

		link = bpf_program__attach_kprobe(exit_progs[i], true, str);
		if (!link) {
			warning("attach call_chain_entry_attach kretprobe attach failed\n");
			goto cleanup;
		}
		free(str);
		str = NULL;
	}

	err = 0;
cleanup:
	if (str)
		free(str);
	return err;
}

static int attach_progs(struct inject_bpf *obj)
{
	struct bpf_link *link = NULL;

	switch (env.mode) {
	case KMALLOC_MODE:
		link = bpf_program__attach_kprobe(obj->progs.should_failslab_entry,
						  false, "should_failslab");
		if (!link) {
			warning("attach should_failslab kprobe attach failed\n");
			return -1;
		}
		break;
	case BIO_MODE:
		link = bpf_program__attach_kprobe(obj->progs.should_fail_bio_entry,
						  false, "should_fail_bio");
		if (!link) {
			warning("attach should_fail_bio kprobe attach failed\n");
			return -1;
		}
		break;
	case ALLOC_PAGE_MODE:
		link = bpf_program__attach_kprobe(obj->progs.should_fail_alloc_page_entry,
						  false, "should_fail_alloc_page");
		if (!link) {
			warning("attach should_fail_alloc_page kprobe attach failed\n");
			return -1;
		}
		break;
	default:
		warning("Not support mode, %d\n", env.mode);
		return -1;
	}

	if (call_chain_entry_attach(obj)) {
		warning("call_chain_entry_attach failed\n");
		return -1;
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

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct inject_bpf *obj = NULL;
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
		return 1;
	}

	if (parse_spec())
		return 1;

	obj = inject_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	obj->rodata->max_stack_depth = env.f_cnt;
	obj->rodata->max_err_count = env.max_err_count;
	obj->rodata->probability = env.probability;
	obj->rodata->enable_flag = env.enable_flag;
	obj->rodata->mode = env.mode;

	err = inject_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = attach_progs(obj);
	if (err) {
		warning("Failed to attch BPF kprobe programs\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (!exiting) {
		sleep(99999999);
	}

cleanup:
	inject_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	return err != 0;
}
