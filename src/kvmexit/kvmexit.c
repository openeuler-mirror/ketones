// SPDX-License-Identifier: GPL-2.0
/*
 *   Jackie Liu <liuyun01@kylinos.cn>
 */
#include "commons.h"
#include "kvmexit.skel.h"
#include "kvmexit.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#include <dirent.h>

#define MAX_WAIT_TIME	99999999
#define PATH_MAX_LENGTH	256

static struct {
	pid_t pid;
	pid_t tid;
	int wait_time;
	int vcpu;
	bool verbose;
	bool alltids;
	bool have_tids;
	pid_t tids[MAX_TIDS];
} env = {
	.wait_time = MAX_WAIT_TIME,
	.vcpu = -1,
};

const char *x86_exit_reasons[] = {
	[0] = "EXCEPTION_NMI",
	[1] = "EXTERNAL_INTERRUPT",
	[2] = "TRIPLE_FAULT",
	[3] = "INIT_SIGNAL",
	[4] = "SIPI_SIGNAL",
	[7] = "INTERRUPT_WINDOW",
	[8] = "NMI_WINDOW",
	[9] = "TASK_SWITCH",
	[10] = "CPUID",
	[12] = "HLT",
	[13] = "INVD",
	[14] = "INVLPG",
	[15] = "RDPMC",
	[16] = "RDTSC",
	[18] = "VMCALL",
	[19] = "VMCLEAR",
	[20] = "VMLAUNCH",
	[21] = "VMPTRLD",
	[22] = "VMPTRST",
	[23] = "VMREAD",
	[24] = "VMRESUME",
	[25] = "VMWRITE",
	[26] = "VMOFF",
	[27] = "VMON",
	[28] = "CR_ACCESS",
	[29] = "DR_ACCESS",
	[30] = "IO_INSTRUCTION",
	[31] = "MSR_READ",
	[32] = "MSR_WRITE",
	[33] = "INVALID_STATE",
	[34] = "MSR_LOAD_FAIL",
	[36] = "MWAIT_INSTRUCTION",
	[37] = "MONITOR_TRAP_FLAG",
	[39] = "MONITOR_INSTRUCTION",
	[40] = "PAUSE_INSTRUCTION",
	[41] = "MCE_DURING_VMENTRY",
	[43] = "TPR_BELOW_THRESHOLD",
	[44] = "APIC_ACCESS",
	[45] = "EOI_INDUCED",
	[46] = "GDTR_IDTR",
	[47] = "LDTR_TR",
	[48] = "EPT_VIOLATION",
	[49] = "EPT_MISCONFIG",
	[50] = "INVEPT",
	[51] = "RDTSCP",
	[52] = "PREEMPTION_TIMER",
	[53] = "INVVPID",
	[54] = "WBINVD",
	[55] = "XSETBV",
	[56] = "APIC_WRITE",
	[57] = "RDRAND",
	[58] = "INVPCID",
	[59] = "VMFUNC",
	[60] = "ENCLS",
	[61] = "RDSEED",
	[62] = "PML_FULL",
	[63] = "XSAVES",
	[64] = "XRSTORS",
	[67] = "UMWAIT",
	[68] = "TPAUSE",
	[74] = "BUS_LOCK",
	[75] = "NOTIFY",
};

const char *argp_program_version = "kvmexit 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
" Display the exit_reason and its statistics of each vm exit\n"
" for all vcpus of all virtual machines. For example:\n"
"\n"
"USAGE: kvmexit [wait-time] [-p PID] [-t TID] [-v vCPU] [-a]\n"
"\n"
"Examples:\n"
"    ./kvmexit                              # Display kvm_exit_reason and its statistics in real-time until Ctrl-C\n"
"    ./kvmexit 5                            # Display in real-time after sleeping 5s\n"
"    ./kvmexit -p 3195281                   # Collpase all tids for pid 3195281 with exit reasons sorted in descending order\n"
"    ./kvmexit -p 3195281 20                # Collpase all tids for pid 3195281 with exit reasons sorted in descending order, and display after sleeping 20s\n"
"    ./kvmexit -p 3195281 -v 0              # Display only vcpu0 for pid 3195281, descending sort by default\n"
"    ./kvmexit -p 3195281 -a                # Display all tids for pid 3195281\n"
"    ./kvmexit -t 395490                    # Display only for tid 395490 with exit reasons sorted in descending order\n"
"    ./kvmexit -t 395490 20                 # Display only for tid 395490 with exit reasons sorted in descending order after sleeping 20s\n"
"    ./kvmexit -T '395490,395491'           # Display for a union like {395490, 395491}\n";

static const struct argp_option opts[] = {
	{ "verbose", 'V', NULL, 0, "Verbose debug output" },
	{ "pid", 'p', "PID", 0, "Collpase all tids for PID with exit reasons" },
	{ "tid", 't', "TID", 0, "Display only for tid 395490 with exit reasons sorted in descending order" },
	{ "cpu", 'c', "CPU", 0, "Display only vcpu0" },
	{ "alltids", 'a', NULL, 0, "Display all tids" },
	{ "vcpu", 'v', "VCPU", 0, "Trace this vcpu only" },
	{ "tids", 'T', "TID1,TID2", 0, "Trace a comma separated series of tids with no space in between" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	char *token;
	int i = 0;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'V':
		env.verbose = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		env.tid = argp_parse_pid(key, arg, state);
		break;
	case 'v':
		env.vcpu = argp_parse_long(key, arg, state);
		break;
	case 'T':
		env.have_tids = true;
		token = strtok(arg, ",");
		while (token != NULL && i < MAX_TIDS) {
			env.tids[i++] = atoi(token);
			token = strtok(NULL, ",");
		}
		break;
	case 'a':
		env.alltids = true;
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0) {
			env.wait_time = argp_parse_long(key, arg, state);
			break;
		} else {
			warning("Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_END:
		if (env.vcpu != -1 && env.alltids) {
			warning("argument -a/--alltids not allowed with argument -v/--vcpu\n");
			argp_usage(state);
		}
		if (env.tid && env.alltids) {
			warning("argument -a/--alltids not allowed with argument -t/--tid\n");
			argp_usage(state);
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

static bool is_intel_architecture(void)
{
	FILE *cpuinfo = fopen("/proc/cpuinfo", "re");
	char line[256];
	bool ret = false;

	if (!cpuinfo) {
		warning("Error opening /proc/cpuinfo\n");
		return false;
	}

	/* Read lines from /proc/cpuinfo */
	while (fgets(line, sizeof(line), cpuinfo)) {
		/* Check if the line contains "vendor_id" and "GenuineIntel" */
		if (strstr(line, "vendor_id") && strstr(line, "GenuineIntel")) {
			ret = true;
			break;
		}
	}

	fclose(cpuinfo);
	return ret;
}

static pid_t compare_comm_with_vcpu(const char *tid, pid_t pid, int vcpu)
{
	char path[PATH_MAX_LENGTH];
	FILE *file;
	char comm[16]; // assuming comm will not exceed 16 characters
	char vcpu_name[16];

	snprintf(path, PATH_MAX_LENGTH, "/proc/%d/task/%s/comm", pid, tid);
	snprintf(vcpu_name, 16, "CPU %d", vcpu);

	file = fopen(path, "r");
	if (!file) {
		warning("Error opening file\n");
		return -1;
	}

	if (fgets(comm, sizeof(comm), file) == NULL) {
		warning("Error reading file\n");
		fclose(file);
		return -1;
	}

	fclose(file);

	// compare comm with "VCPU ID"
	if (strstr(comm, vcpu_name))
		return atoi(tid);

	return -1;
}

static pid_t find_tid(pid_t pid, int vcpu)
{
	char path[PATH_MAX_LENGTH];
	DIR *dir;
	struct dirent *entry;
	pid_t tid = -1;

	snprintf(path, PATH_MAX_LENGTH, "/proc/%d/task", pid);

	if ((dir = opendir(path)) == NULL) {
		warning("Error opening directory\n");
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type == DT_DIR && atoi(entry->d_name) != 0) {
			tid = compare_comm_with_vcpu(entry->d_name, pid, vcpu);
			if (tid != -1)
				break;
		}
	}

	closedir(dir);
	return tid;
}

static void print_header(void)
{
	printf("Display kvm exit reasons and statistics for ");
	if (env.tid) {
		printf("TID %d", env.tid);
	} else if (env.have_tids) {
		printf("TIDS [");
		for (int i = 0; i < MAX_TIDS && env.tids[i]; i++) {
			if (i != 0)
				printf(", ");
			printf("'%d'", env.tids[i]);
		}
		printf("]");
	} else if (env.pid) {
		if (env.vcpu != -1)
			printf("PID %d VCPU %d", env.pid, env.vcpu);
		else if (env.alltids)
			printf("PID %d and its all threads", env.pid);
		else
			printf("PID %d", env.pid);
	} else {
		printf("all threads");
	}

	if (env.wait_time != MAX_WAIT_TIME)
		printf(" after sleeping %d secs.\n", env.wait_time);
	else
		printf("... Hit Ctrl-C to end.\n");

	sleep(env.wait_time);
	if (env.wait_time == MAX_WAIT_TIME)
		printf("\n");

	if (env.tid) {
	} else if (env.have_tids) {
		printf("TIDS      ");
	} else if (env.pid) {
		if (env.vcpu == -1 && env.alltids)
			printf("TID      ");
	} else {
		printf("PID      TID      ");
	}

	printf("%-35s %s\n", "KVM_EXIT_REASON", "COUNT");
}

struct exit_count_info {
	__u64 exit_count;
	int index;
};

static int sort_column(const void *obj1, const void *obj2)
{
	const struct exit_count_info *i1 = obj1;
	const struct exit_count_info *i2 = obj2;

	return i2->exit_count - i1->exit_count;
}

static int print_maps(struct kvmexit_bpf *obj)
{
	int pcpu_kvm_stat_map_fd = bpf_map__fd(obj->maps.pcpu_kvm_stat);
	int pcpu_cache_map_fd = bpf_map__fd(obj->maps.pcpu_cache);
	long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	__u64 key = -1, pid_tgid;
	struct exit_count *exit_counts;
	struct cache_info *pcpu_cache;
	int ret = 0;
	struct exit_count_info eci[REASON_NUM] = {};
	int count = 0;

	print_header();

	pcpu_cache = malloc(sizeof(struct cache_info) * num_cpus);
	if (!pcpu_cache) {
		warning("Failed to alloc memory\n");
		return -1;
	}

	exit_counts = malloc(sizeof(struct exit_count) * num_cpus);
	if (!exit_counts) {
		warning("Failed to alloc memory\n");
		free(pcpu_cache);
		return -1;
	}

	while (!bpf_map_get_next_key(pcpu_kvm_stat_map_fd, &key, &pid_tgid)) {
		pid_t pid, tid;
		int zero = 0;

		if (bpf_map_lookup_elem(pcpu_kvm_stat_map_fd, &pid_tgid, exit_counts)) {
			warning("Error looking up map element\n");
			ret = -1;
			goto cleanup;
		}

		pid = pid_tgid >> 32;
		tid = pid_tgid & 0xffffffff;

		if (bpf_map_lookup_elem(pcpu_cache_map_fd, &zero, pcpu_cache)) {
			warning("Error looking up map element\n");
			ret = -1;
			goto cleanup;
		}

		for (int i = 0; i < ARRAY_SIZE(x86_exit_reasons); i++) {
			int sum = 0;

			for (int inner_cpu = 0; inner_cpu < num_cpus; inner_cpu++) {
				__u64 cache_pid_tgid = pcpu_cache[inner_cpu].cache_pid_tgid;
				if (cache_pid_tgid == pid_tgid)
					sum += pcpu_cache[inner_cpu].cache_exit_ct.exit_ct[i];
				else
					sum += exit_counts[inner_cpu].exit_ct[i];
			}

			if (sum == 0)
				continue;

			if ((env.pid && !env.alltids) || env.tid == tid) {
				eci[i].exit_count += sum;
				eci[i].index = i;
				/* how many exit reason count array we have */
				count++;
			} else if (env.alltids || env.have_tids) {
				printf("%-8u %-35s %-8u\n", tid, x86_exit_reasons[i], sum);
			} else {
				printf("%-8u %-8u %-35s %-8u\n", pid, tid, x86_exit_reasons[i], sum);
			}
		}

		key = pid_tgid;
	}

	if (count != 0) {
		qsort(&eci, REASON_NUM, sizeof(struct exit_count_info), sort_column);

		for (int i = 0; eci[i].exit_count; i++)
			printf("%-35s %-8llu\n", x86_exit_reasons[eci[i].index], eci[i].exit_count);
	}

cleanup:
	free(exit_counts);
	free(pcpu_cache);

	return ret;
}

static void sig_handler(int sig)
{}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct kvmexit_bpf *obj;
	int err;

	if (!is_intel_architecture()) {
		warning("Currently we only support Intel architecture, please do expansion if needs more.\n");
		return 1;
	}

	if (!bpf_is_root())
		return 1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return err;
	}

	libbpf_set_print(libbpf_print_fn);
	obj = kvmexit_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	if (!obj->bss) {
		warning("Memory-mapping BPF maps is supported starting from Linux 5.7, please upgrade.\n");
		env.have_tids = false;
	}

	if (env.tid) {
		obj->rodata->target_tid = env.tid;
	} else if (env.have_tids) {
		for (int i = 0; i < MAX_TIDS && env.tids[i]; i++)
			obj->bss->target_tids[i] = env.tids[i];
	} else if (env.pid) {
		obj->rodata->target_pid = env.pid;
		if (env.vcpu != -1)
			obj->rodata->target_tid = find_tid(env.pid, env.vcpu);
	}

	if (!tracepoint_exists("kvm", "kvm_exit")) {
		warning("Maybe kvm is not enabled, insmod kvm.ko?\n");
		goto cleanup;
	}

	if (probe_tp_btf("kvm_exit"))
		bpf_program__set_autoload(obj->progs.tracepoint_kvm_exit_raw, false);
	else
		bpf_program__set_autoload(obj->progs.tracepoint_kvm_exit_btf, false);

	err = kvmexit_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = kvmexit_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		err = 1;
		warning("Failed to set signal handler\n");
		goto cleanup;
	}

	err = print_maps(obj);

cleanup:
	kvmexit_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
