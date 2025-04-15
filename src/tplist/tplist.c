// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Youling Tang <tangyouling@kylinos.cn>
//
// Base on tplist.py - Copyright 2016, Sasha Goldshtein
#include "commons.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"
#include <dirent.h>
#include <regex.h>

static struct {
	int verbose;
	pid_t pid;
	const char *lib;
} env = {
	.verbose = 0,
	.pid = -1,
	.lib = "",
};

const char *argp_program_version = "tplist 0.1";
const char *argp_program_bug_address = "Youling Tang <tangyouling@kylinos.cn>";
const char argp_program_doc[] =
"Display kernel tracepoints or USDT probes and their formats.\n"
"\n"
"USAGE: tplist [-p PID] [-l LIB] [-v] [filter]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Increase verbosity level (print variables, arguments, etc.)", 0 },
	{ "pid", 'p', "PID", 0, "List USDT probes in the specified process", 0 },
	{ "lib", 'l', "LIB", 0, "List USDT probes in the specified library or executable", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

#define MAX_PATH_LEN	256

static char root[MAX_PATH_LEN * 3];

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose++;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'l':
		env.lib = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static void print_tpoint_format(const char *category, const char *event)
{
	regex_t regex;
	regmatch_t match[2];
	char fmt_path[MAX_PATH_LEN * 4];
	char *buffer = NULL;
	char field_name[50];
	FILE *file;
	size_t length = 0;

	if (regcomp(&regex, "field:([^;]*);", REG_EXTENDED) != 0) {
		warning("Failed to compile regex\n");
		return;
	}

	sprintf(fmt_path, "%s/format", root);
	file = fopen(fmt_path, "r");
	if (!file)
		return;

	while (getline(&buffer, &length, file) != -1) {
		if (regexec(&regex, buffer, 2, match, 0) == 0) {
			strncpy(field_name, buffer + match[1].rm_so,
				match[1].rm_eo - match[1].rm_so);
			field_name[match[1].rm_eo - match[1].rm_so] = 0;

			if (strstr(field_name, "common_"))
				continue;

			printf("    %s;\n", field_name);
		}
	}

	free(buffer);
	fclose(file);
	regfree(&regex);
}

static void print_tpoint(const char *category, const char *event)
{
	printf("%s:%s\n", category, event);

	if (env.verbose > 0)
		print_tpoint_format(category, event);
}

static void print_tracepoints()
{
	char category[MAX_PATH_LEN];
	char event_root[MAX_PATH_LEN];
	DIR *dir, *cat_dir, *evt_dir;
	struct dirent *entry, *cat_entry;

	snprintf(event_root, sizeof(event_root), "%s/events", tracefs_path());
	dir = opendir(event_root);
	if(!dir)
		return;

	while((entry = readdir(dir)) != NULL) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;

		sprintf(root, "%s/%s", event_root, entry->d_name);
		cat_dir = opendir(root);
		if (!cat_dir)
			continue;

		memcpy(category, entry->d_name, sizeof(category));

		while((cat_entry = readdir(cat_dir)) != NULL) {
			if (!strcmp(cat_entry->d_name, ".") ||
			    !strcmp(cat_entry->d_name, ".."))
				continue;

			sprintf(root, "%s/%s/%s", event_root, category, cat_entry->d_name);
			evt_dir = opendir(root);
			if (!evt_dir)
				continue;

			print_tpoint(category, cat_entry->d_name);
			closedir(evt_dir);
		}
		closedir(cat_dir);

	}
	closedir(dir);
}

static void print_usdt_simple(struct usdt_array *usdt_notes, char *binary_path)
{
	size_t i;

	for (i = 0; i < usdt_notes->nr; i++)
		printf("b'%s' b'%s':b'%s'\n", binary_path, usdt_notes->notes[i].provider,
			usdt_notes->notes[i].name);
}

static void print_usdt_details(struct usdt_array *usdt_notes)
{
	size_t i;

	printf("%-15s  %-40s  %-18s  %-18s  %-18s  %s\n", "PROVIDER", "NAME", "LOC_ADDR",
		"BASE_ADDR", "SEMA_ADDR", "ARGS");
	for (i = 0; i < usdt_notes->nr; i++)
		printf("%-15s  %-40s  0x%016lx  0x%016lx  0x%016lx  %s\n", usdt_notes->notes[i].provider,
			usdt_notes->notes[i].name, usdt_notes->notes[i].loc_addr,
			usdt_notes->notes[i].base_addr, usdt_notes->notes[i].sema_addr,
			usdt_notes->notes[i].args);
}

static void print_usdt()
{
	char binary_path[PATH_MAX];
	struct usdt_array *usdt_notes = NULL;

	resolve_binary_path(env.lib, env.pid, binary_path, sizeof(binary_path));
	usdt_notes = probe_usdt_notes(binary_path);
	if (!usdt_notes)
		return;

	if (env.verbose)
		print_usdt_details(usdt_notes);
	else
		print_usdt_simple(usdt_notes, binary_path);

	free_usdt_notes(usdt_notes);
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

	if ((env.pid == -1) && !env.lib[0])
		print_tracepoints();
	else
		print_usdt();

	return err != 0;
}
