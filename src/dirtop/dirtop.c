// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on dirtop.py - Erwan Velu

#include "commons.h"
#include "dirtop.h"
#include "dirtop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include <sys/stat.h>

enum SORT {
	ALL,
	READS,
	WRITES,
	RBYTES,
	WBYTES,
};

struct dir_stat {
	int reads;
	int writes;
	int reads_Kb;
	int writes_Kb;
	int index;
};

static volatile sig_atomic_t exiting;
static int inodes_number = 0;
static __u32 dir_ids[MAX_DIR_NUM];
static char dir_name[MAX_DIR_NUM][PATH_NAME_LEN];
static volatile int sort_by = ALL;

static struct env {
	bool verbose;
	bool clear;
	int interval;
	pid_t pid;
	char *rootdirs;
} env = {
	.clear		= true,
	.pid		= 0,
	.interval	= 1,
};

const char *argp_program_version = "dirtop 0.1";
const char *argp_program_bug_address = "Yang Feng <yangfeng@kylinos.cn>";
const char argp_program_doc[] =
"dirtop shows reads and writes by directory.\n"
"\n"
"USAGE: dirtop -d ROOTDIRS [-v] [-h] [-C] [-p PID] [-i INTERVAL] [-s {all,reads,writes,rbytes,wbytes}]\n"
"\n"
"Example:\n"
"    dirtop  -d '/hdfs/uuid/*/yarn'                   # directory I/O top, 1 second refresh\n"
"    dirtop  -d '/hdfs/uuid/*/yarn' -C                # don't clear the screen\n"
"    dirtop  -d '/hdfs/uuid/*/yarn' -i 5              # 5 second summaries\n"
"    dirtop  -d '/hdfs/uuid/*/yarn,/hdfs/uuid/*/data' # Running dirtop on two set of directories\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "noclear", 'C', NULL, 0, "don't clear the screen", 0 },
	{ "sort", 's', "SORT", 0, "Sort columns, default all [all, reads, writes, rbytes, wbytes]", 0 },
	{ "root-directories", 'd', "ROOTDIRS", 0, "select the directories to observe, separated by commas", 0 },
	{ "pid", 'p', "PID", 0, "Trace process ID only", 0 },
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
	case 'C':
		env.clear = false;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'd':
		env.rootdirs = arg;
		break;
	case 's':
		if (!strcmp(arg, "all"))
			sort_by = ALL;
		else if (!strcmp(arg, "reads"))
			sort_by = READS;
		else if (!strcmp(arg, "writes"))
			sort_by = WRITES;
		else if (!strcmp(arg, "rbytes"))
			sort_by = RBYTES;
		else if (!strcmp(arg, "wbytes"))
			sort_by = WBYTES;
		else {
			warning("Invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (!env.rootdirs) {
			printf("%s\n", argp_program_doc);
			printf("error: the following arguments are required: -d\n");
			return ARGP_KEY_ERROR;
		}
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

static int get_searched_ids(struct dirtop_bpf *obj)
{
	FILE *fp;
	char buffer[PATH_NAME_LEN];
	struct stat file_stat;
	int rc;
	char path[PATH_NAME_LEN];
	int i = 0;
	char *current_path;

	if (!env.rootdirs) {
		warning("Need to set up files\n");
		return -EINVAL;
	}

	current_path = strtok(env.rootdirs, ",");
	while (current_path != NULL) {
		sprintf(path, "%s %s", "realpath", current_path);
		fp = popen(path, "r");
		if (fp == NULL) {
			warning("Failed %s\n", path);
			return -EINVAL;
		}

		while (fgets(buffer, sizeof(buffer), fp) != NULL) {
			if (inodes_number >= MAX_DIR_NUM) {
				warning("%d directories limit reached\n", MAX_DIR_NUM);
				break;
			}

			// Remove the end '\n'
			buffer[strlen(buffer) - 1] = '\0';
			rc = stat(buffer, &file_stat);
			if (rc != 0) {
				perror("stat");
				return -EINVAL;
			}

			// duplicate removal
			for (i = 0; i < inodes_number; ++i) {
				if (dir_ids[i] == file_stat.st_ino)
					break;
			}
			if (i != inodes_number)
				continue;

			dir_ids[inodes_number] = file_stat.st_ino;
			obj->rodata->dir_ids[inodes_number] = dir_ids[inodes_number];
			strcpy(dir_name[inodes_number++], buffer);
			printf("Considering %s with inode_id %ld\n", buffer, file_stat.st_ino);
		}
		pclose(fp);
		current_path = strtok(NULL, ",");
	}
	obj->rodata->inodes_number = inodes_number;

	return 0;
}

static int sort_column(const void *obj1, const void *obj2)
{
	struct dir_stat *s1 = (struct dir_stat *)obj1;
	struct dir_stat *s2 = (struct dir_stat *)obj2;

	if (sort_by == READS)
		return s2->reads - s1->reads;
	else if (sort_by == WRITES)
		return s2->writes - s1->writes;
	else if (sort_by == RBYTES)
		return s2->reads_Kb - s1->reads_Kb;
	else if (sort_by == WBYTES)
		return s2->writes_Kb - s1->writes_Kb;
	else
		return (s2->reads + s2->writes + s2->reads_Kb + s2->writes_Kb) -
			(s1->reads + s1->writes + s1->reads_Kb + s1->writes_Kb);
}

static int handle_data(struct dirtop_bpf *obj)
{
	FILE *file;
	char buffer[PATH_NAME_LEN];
	char time[16];
	struct key_t lookup_key = { .inode_id = -1 }, next_key;
	struct val_t info;
	struct dir_stat dir_stat[MAX_DIR_NUM] = { 0 };
	int err;
	int fd = bpf_map__fd(obj->maps.counts);

	file = fopen("/proc/loadavg", "r");
	if (file == NULL) {
		warning("Failed open /proc/loadavg\n");
		return -1;
	}
	while (fgets(buffer, sizeof(buffer), file) != NULL);
	fclose(file);

	printf("%-8s loadavg: %s\n", strftime_now(time, sizeof(time), "%H:%M:%S"), buffer);
	printf("%-6s %-6s %-8s %-8s %s\n", "READS", "WRITES", "R_Kb", "W_Kb", "PATH");

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		lookup_key = next_key;
		err = bpf_map_lookup_elem(fd, &next_key, &info);
		if (err < 0) {
			warning("Failed to lookup infos: %d\n", err);
			return err;
		}
		for (int i = 0; i < inodes_number; ++i) {
			if (dir_ids[i] == next_key.inode_id) {
				dir_stat[i].reads += info.reads;
				dir_stat[i].writes += info.writes;
				dir_stat[i].reads_Kb += info.rbytes / 1024;
				dir_stat[i].writes_Kb += info.wbytes / 1024;
				dir_stat[i].index = i;
			}
		}
	}

	qsort(dir_stat, inodes_number, sizeof(struct dir_stat), sort_column);
	for (int i = 0; i < inodes_number; ++i) {
		if (dir_stat[i].reads != 0 || dir_stat[i].writes != 0 ||
		    dir_stat[i].reads_Kb != 0 || dir_stat[i].writes_Kb != 0)
			printf("%-6d %-6d %-8d %-8d %s\n",
				dir_stat[i].reads, dir_stat[i].writes,
				dir_stat[i].reads_Kb, dir_stat[i].writes_Kb,
				dir_name[dir_stat[i].index]);
	}

	/* Clear the map */
	lookup_key.inode_id = -1;
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
	DEFINE_SKEL_OBJECT(obj);
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

	obj = SKEL_OPEN_OPTS(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	obj->rodata->target_tgid = env.pid;
	err = get_searched_ids(obj);
	if (err) {
		warning("Failed to get_searched_ids: %d\n", err);
		goto cleanup;
	}

	if (fentry_can_attach("vfs_read", NULL)) {
		bpf_program__set_autoload(obj->progs.trace_read_entry_kprobe, false);
		bpf_program__set_autoload(obj->progs.trace_write_entry_kprobe, false);
	} else {
		bpf_program__set_autoload(obj->progs.trace_read_entry_fentry, false);
		bpf_program__set_autoload(obj->progs.trace_write_entry_fentry, false);
	}

	err = SKEL_LOAD(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = SKEL_ATTACH(obj);
	if (err) {
		warning("Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("Tracing ... Output every %d secs. Hit Ctrl-C to end\n", env.interval);

	while (!exiting) {
		sleep(env.interval);
		if (env.clear)
			system("clear");

		err = handle_data(obj);
		if (err) {
			warning("Failed to handle_data: %d\n", err);
			goto cleanup;
		}
	}

cleanup:
	SKEL_DESTROY(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
