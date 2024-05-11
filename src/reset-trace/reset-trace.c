// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Base on reset-trace.py - COPYRIGHT: Copyright (c) 2016 Brendan Gregg.
#include "commons.h"
#include "trace_helpers.h"

static struct {
	bool verbose;
	bool force;
	bool quiet;
} env;

const char *argp_program_version = "reset-trace 0.1";
const char *argp_program_bug_address = "Youling Tang <tangyouling@kylinos.cn>";
const char argp_program_doc[] =
"Reset state of tracing, disabling all tracing.\n"
"\n"
"USAGE: reset-trace [-Fhqv]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "print details while working", 0 },
	{ "force", 'F', NULL, 0, "reset all tracing files", 0 },
	{ "quiet", 'q', NULL, 0, "no output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

#define MAX_PATH_LEN	256

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'F':
		env.force = true;
		break;
	case 'q':
		env.quiet = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

#define verbose_printf(format, ...)		\
	if (env.verbose)			\
		printf(format, ##__VA_ARGS__);


static void writefile(const char *file, const char *write, const char *expected)
{
	char path[MAX_PATH_LEN];
	const char *tracing = tracefs_path();
	char buf[1024] ={0};
	int line = 0;
	FILE *fd;

	snprintf(path, sizeof(path), "%s/%s", tracing, file);
	if (access(path, W_OK))
		warning("WARNING: file %s doesn't writable/exists. Skipping.\n", path);

	verbose_printf("Checking %s\n", path);

	fd = fopen(path, "r");
	if (!fd) {
		printf("fopen %s failed.\n", path);
		return;
	}

	/* filter */
	while (fgets(buf, sizeof(buf), fd)) {
		if (buf[0] == '#')
			continue;
		if (!strncmp(buf, expected, strlen(buf) - 1))
			goto out;
		line++;
	}
	if (!line)
		goto out;

	if (!env.quiet)
		printf("Needed to reset %s\n", path);
	verbose_printf("%s, before (line enumerated):\n", file);

	line = 0;
	/* rewind to the start */
	fseek(fd, 0, SEEK_SET);
	while (fgets(buf, sizeof(buf), fd))
		verbose_printf("%6d\t%s", ++line, buf);

	fclose(fd);

	fd = fopen(path, "w+");
	if (!fd) {
		printf("fopen %s failed.\n", path);
		return;
	}

	if (fwrite(write, 1, strlen(write), fd) != strlen(write))
		warning("WARNING: write %s failed. %ld\n", write, strlen(write));

	verbose_printf("%s, after (line enumerated):\n", file);
	memset(buf, 0, sizeof(buf));

	/* rewind to the start */
	fseek(fd, 0, SEEK_SET);
	line = 0;
	while (fgets(buf, sizeof(buf), fd))
		verbose_printf("%6d\t%s", ++line, buf);
	verbose_printf("\n");

out:
	fclose(fd);
}

/* Only write when force is used */
static void checkfile(const char *file, const char *write, const char *expected)
{
	char path[MAX_PATH_LEN];
	const char *tracing = tracefs_path();
	char buf[1024] ={0};
	int line = 0;
	FILE *fd;

	snprintf(path, sizeof(path), "%s/%s", tracing, file);
	if (access(path, F_OK))
		warning("WARNING: file %s doesn't exist. Skipping.\n", path);

	if (env.force) {
		writefile(file, write, expected);
		return;
	}

	if (env.quiet)
		return;

	verbose_printf("Checking %s\n", path);

	fd = fopen(path, "r");
	if (!fd) {
		printf("open %s failed.\n", path);
		return;
	}

	/* filter */
	while (fgets(buf, sizeof(buf), fd)) {
		if (buf[0] == '#')
			continue;
		if (!strncmp(buf, expected, strlen(buf) - 1))
			goto out;
		line++;
	}
	if (!line)
		goto out;

	printf("Noticed unrelated tracing file %s isn't set as expected. "
		"Not resetting (-F to force, -v for verbose).\n", path);
	verbose_printf("Contents of %s is (line enumerated):\n", file);

	line = 0;
	/* rewind to the start */
	fseek(fd, 0, SEEK_SET);
	while (fgets(buf, sizeof(buf), fd))
		verbose_printf("%6d\t%s", ++line, buf);

	verbose_printf("Expected \"%s\".\n", expected);

out:
	fclose(fd);
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	verbose_printf("Resetting tracing state...\n\n");

	writefile("kprobe_events", "", "");
	writefile("uprobe_events", "", "");
	/* clears trace_pipe */
	writefile("trace", "", "");

	checkfile("current_tracer", "nop", "nop");
	checkfile("set_ftrace_filter", "", "");
	checkfile("set_graph_function", "", "");
	checkfile("set_ftrace_pid", "", "no pid");
	checkfile("events/enable", "0", "0");
	checkfile("tracing_thresh", "0", "0");
	checkfile("tracing_on", "1", "1");

	verbose_printf("\nDone.\n");

	return err != 0;
}
