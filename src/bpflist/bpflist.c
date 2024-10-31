// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>
//
// Idea by Brendan Gregg.
// Base on bpflist-bpfcc(8) - Copyright 2017, Sasha Goldshtein
#include "commons.h"
#include <dirent.h>
#include <regex.h>

static int verbose = 0;

const char *argp_program_version = "bpflist 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Display processes currently using BPF programs and maps, pinned BPF programs"
" and maps, and enabled probes.\n"
"\n"
"USAGE: bpflist [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "also count kprobes/uprobes" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		verbose++;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

#define MAX_PATH_LEN	256

static char *comm_for_pid(const char *pid)
{
	char comm_path[MAX_PATH_LEN];
	snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", pid);

	FILE *file = fopen(comm_path, "r");
	if (!file)
		return "[unknown]";

	char *buffer = NULL;
	size_t length = 0;
	ssize_t read;

	read = getline(&buffer, &length, file);
	fclose(file);

	if (read == -1) {
		if (buffer)
			free(buffer);
		return "[unknown]";
	}

	if (buffer[read - 1] == '\n')
		buffer[read - 1] = 0;

	return buffer;
}

static void find_bpf_fds(const char *pid)
{
	char root[MAX_PATH_LEN];
	char *buffer;
	DIR *dir;
	struct dirent *entry;
	regex_t regex;
	regmatch_t match[2];
	int counts_size = 0;
	struct {
		char bpf_name[MAX_PATH_LEN];
		int count;
	} counts[256];

	if (regcomp(&regex, "anon_inode:bpf-(\\w+)", REG_EXTENDED) != 0) {
		warning("Failed to compile regex\n");
		return;
	}

	snprintf(root, sizeof(root), "/proc/%s/fd", pid);
	dir = opendir(root);
	if (!dir)
		return;

	while ((entry = readdir(dir)) != NULL) {
		char fd_path[MAX_PATH_LEN*2];
		char link_target[MAX_PATH_LEN];
		size_t link_len;

		sprintf(fd_path, "%s/%s", root, entry->d_name);
		link_len = readlink(fd_path, link_target, MAX_PATH_LEN - 1);
		if (link_len == -1)
			continue;
		link_target[link_len] = 0;

		if (regexec(&regex, link_target, 2, match, 0) == 0) {
			char bpf_name[MAX_PATH_LEN];
			bool found = false;

			strncpy(bpf_name, link_target + match[1].rm_so,
				match[1].rm_eo - match[1].rm_so);
			bpf_name[match[1].rm_eo - match[1].rm_so] = 0;

			for (int i = 0; i < counts_size; i++) {
				if (strcmp(counts[i].bpf_name, bpf_name) == 0) {
					counts[i].count++;
					found = true;
					break;
				}
			}

			if (!found) {
				counts[counts_size].count = 1;
				strncpy(counts[counts_size].bpf_name, bpf_name, MAX_PATH_LEN);
				counts_size++;
			}
		}
	}

	buffer = comm_for_pid(pid);
	for (int i = 0; i < counts_size; i++)
		printf("%-7s %-16s %-8s %-4d\n", pid, buffer,
		       counts[i].bpf_name, counts[i].count);

	free(buffer);
	closedir(dir);
	regfree(&regex);
}

int main(int argc, char *argv[])
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	int err;
	DIR *dir;
	struct dirent *entry;
	regex_t regex;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	if (regcomp(&regex, "^[0-9]+$", REG_EXTENDED | REG_NOSUB) != 0) {
		warning("Failed to compile regex\n");
		return 1;
	}

	dir = opendir("/proc");
	if (!dir) {
		warning("Failed to open /proc directory\n");
		return 1;
	}

	printf("%-7s %-16s %-8s %s\n", "PID", "COMM", "TYPE", "COUNT");
	while ((entry = readdir(dir)) != NULL) {
		if (regexec(&regex, entry->d_name, 0, NULL, 0) == 0)
			find_bpf_fds(entry->d_name);
	}

	closedir(dir);
	regfree(&regex);

	return err != 0;
}
