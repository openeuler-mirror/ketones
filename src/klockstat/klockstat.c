// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "klockstat.h"
#include "klockstat.skel.h"
#include "trace_helpers.h"
#include "compat.h"
#include <sys/param.h>

enum {
	SORT_ACQ_MAX,
	SORT_ACQ_COUNT,
	SORT_ACQ_TOTAL,
	SORT_HLD_MAX,
	SORT_HLD_COUNT,
	SORT_HLD_TOTAL,
};

static struct prog_env {
	pid_t pid;
	pid_t tid;
	char *caller;
	char *lock_name;
	unsigned int nr_locks;
	unsigned int nr_stack_entries;
	unsigned int sort_acq;
	unsigned int sort_hld;
	unsigned int duration;
	unsigned int interval;
	unsigned int iterations;
	bool reset;
	bool timestamp;
	bool verbose;
	bool per_thread;
} env = {
	.nr_locks = 99999999,
	.nr_stack_entries = 1,
	.sort_acq = SORT_ACQ_MAX,
	.sort_hld = SORT_HLD_MAX,
	.interval = 99999999,
	.iterations = 99999999,
};

const char *argp_program_version = "klockstat 0.2";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
static const char args_doc[] = "FUNCTION";
static const char argp_program_doc[] =
"Trace mutex/sem lock acquisition and hold times, in nsec\n"
"\n"
"Usage: klockstat [-hPRTv] [-p PID] [-t TID] [-c FUNC] [-L LOCK] [-n NR_LOCKS]\n"
"                 [-s NR_STACKS] [-S SORT] [-d DURATION] [-i INTERVAL]\n"
"\v"
"Examples:\n"
"  klockstat                     # trace system wide until ctrl-c\n"
"  klockstat -d 5                # trace for 5 seconds\n"
"  klockstat -i 5                # print stats every 5 seconds\n"
"  klockstat -p 181              # trace process 181 only\n"
"  klockstat -t 181              # trace thread 181 only\n"
"  klockstat -c pipe_            # print only for lock callers with 'pipe_'\n"
"                                # prefix\n"
"  klockstat -L cgroup_mutex     # trace the cgroup_mutex lock only (accepts addr too)\n"
"  klockstat -S acq_count        # sort lock acquired results by acquire count\n"
"  klockstat -S hld_total        # sort lock held results by total held time\n"
"  klockstat -S acq_count,hld_total  # combination of above\n"
"  klockstat -n 3                # display top 3 locks/threads\n"
"  klockstat -s 6                # display 6 stack entries per lock\n"
"  klockstat -P                  # print stats per thread\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Filter by process ID", 0 },
	{ "tid", 't', "TID", 0, "Filter by thread ID", 0 },
	{ 0, 0, 0, 0, "", 0 },
	{ "caller", 'c', "FUNC", 0, "Filter by caller string prefix ", 0 },
	{ "lock", 'L', "LOCK", 0, "Filter by specific ksym lock name", 0 },
	{ 0, 0, 0, 0, "", 0 },
	{ "locks", 'n', "NR_LOCKS", 0, "Number of locks or threads to print", 0 },
	{ "stacks", 's', "NR_STACKS", 0, "Number of stack entries to print per lock", 0 },
	{ "sort", 'S', "SORT", 0, "Sort by field:\n  acq_[max|total|count]\n  hld_[max|total|count]", 0 },
	{ 0, 0, 0, 0, "", 0 },
	{ "duration", 'd', "SECONDS", 0, "Duration to trace", 0 },
	{ "interval", 'i', "SECONDS", 0, "Print interval", 0 },
	{ "reset", 'R', NULL, 0, "Reset stats each interval", 0 },
	{ "timestamp", 'T', NULL, 0, "Print timestamp", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "per-thread", 'P', NULL, 0, "Print per-thread stats", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

static void *parse_lock_addr(const char *lock_name)
{
	unsigned long lock_addr;

	return sscanf(lock_name, "0x%lx", &lock_addr) ? (void *)lock_addr : NULL;
}

static void *get_lock_addr(struct ksyms *ksyms, const char *lock_name)
{
	const struct ksym *ksym = ksyms__get_symbol(ksyms, lock_name);

	return ksym ? (void *)ksym->addr : parse_lock_addr(lock_name);
}

static const char *get_lock_name(struct ksyms *ksyms, unsigned long addr)
{
	const struct ksym *ksym = ksyms__map_addr(ksyms, addr);

	return (ksym && ksym->addr == addr) ? ksym->name : "no-ksym";
}

static bool parse_one_sort(struct prog_env *env, const char *sort)
{
	const char *field = sort + 4;

	if (!strncmp(sort, "acq_", 4)) {
		if (!strcmp(field, "max")) {
			env->sort_acq = SORT_ACQ_MAX;
			return true;
		} else if (!strcmp(field, "total")) {
			env->sort_acq = SORT_ACQ_TOTAL;
			return true;
		} else if (!strcmp(field, "count")) {
			env->sort_acq = SORT_ACQ_COUNT;
			return true;
		}
	} else if (!strncmp(sort, "hld_", 4)) {
		if (!strcmp(field, "max")) {
			env->sort_hld = SORT_HLD_MAX;
			return true;
		} else if (!strcmp(field, "total")) {
			env->sort_hld = SORT_HLD_TOTAL;
			return true;
		} else if (!strcmp(field, "count")) {
			env->sort_hld = SORT_HLD_COUNT;
			return true;
		}
	}

	return false;
}

static bool parse_sorts(struct prog_env *env, char *arg)
{
	char *comma = strchr(arg, ',');

	if (comma) {
		*comma = '\0';
		comma++;
		if (!parse_one_sort(env, comma))
			return false;
	}
	return parse_one_sort(env, arg);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct prog_env *env = state->input;

	switch (key) {
	case 'p':
		env->pid = argp_parse_pid(key, arg, state);
		break;
	case 't':
		errno = 0;
		env->tid = strtol(arg, NULL, 10);
		if (errno || env->tid <= 0) {
			warning("Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		env->caller = arg;
		break;
	case 'L':
		env->lock_name = arg;
		break;
	case 'n':
		errno = 0;
		env->nr_locks = strtol(arg, NULL, 10);
		if (errno || env->nr_locks <= 0) {
			warning("Invalid NR_LOCKS: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 's':
		errno = 0;
		env->nr_stack_entries = strtol(arg, NULL, 10);
		if (errno || env->nr_stack_entries <= 0) {
			warning("Invalid NR_STACKS: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'S':
		if (!parse_sorts(env, arg)) {
			warning("Bad sort string: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		errno = 0;
		env->duration = strtol(arg, NULL, 10);
		if (errno || env->duration <= 0) {
			warning("Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'i':
		errno = 0;
		env->interval = strtol(arg, NULL, 10);
		if (errno || env->interval <= 0) {
			warning("Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'R':
		env->reset = true;
		break;
	case 'T':
		env->timestamp = true;
		break;
	case 'P':
		env->per_thread = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env->verbose = true;
		break;
	case ARGP_KEY_END:
		if (env->duration) {
			env->interval = min(env->interval, env->duration);
			env->iterations = env->duration / env->interval;
		}
		if (env->per_thread && env->nr_stack_entries != 1) {
			warning("--per-thread and --stacks cannot be used together\n");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

struct stack_stat {
	uint32_t stack_id;
	struct lock_stat ls;
	uint64_t bt[PERF_MAX_STACK_DEPTH];
};

static bool caller_is_traced(struct ksyms *ksyms, uint64_t caller_pc)
{
	const struct ksym *ksym;

	if (!env.caller)
		return true;
	ksym = ksyms__map_addr(ksyms, caller_pc);
	if (!ksym)
		return true;
	return strncmp(env.caller, ksym->name, strlen(env.caller)) == 0;
}

static int larger_first(uint64_t x, uint64_t y)
{
	if (x > y)
		return -1;
	if (x == y)
		return 0;
	return 1;
}

static int sort_by_acq(const void *x, const void *y)
{
	struct stack_stat *ss_x = *(struct stack_stat **)x;
	struct stack_stat *ss_y = *(struct stack_stat **)y;

	switch (env.sort_acq) {
	case SORT_ACQ_MAX:
		return larger_first(ss_x->ls.acq_max_time,
				    ss_y->ls.acq_max_time);
	case SORT_ACQ_COUNT:
		return larger_first(ss_x->ls.acq_count,
				    ss_y->ls.acq_count);
	case SORT_ACQ_TOTAL:
		return larger_first(ss_x->ls.acq_total_time,
				    ss_y->ls.acq_total_time);
	}

	warning("Bad sort_acq %d\n", env.sort_acq);
	return -1;
}

static int sort_by_hld(const void *x, const void *y)
{
	struct stack_stat *ss_x = *(struct stack_stat **)x;
	struct stack_stat *ss_y = *(struct stack_stat **)y;

	switch (env.sort_hld) {
	case SORT_HLD_MAX:
		return larger_first(ss_x->ls.hld_max_time,
				    ss_y->ls.hld_max_time);
	case SORT_HLD_COUNT:
		return larger_first(ss_x->ls.hld_count,
				    ss_y->ls.hld_count);
	case SORT_HLD_TOTAL:
		return larger_first(ss_x->ls.hld_total_time,
				    ss_y->ls.hld_total_time);
	}

	warning("Bad sort_hld %d\n", env.sort_hld);
	return -1;
}

static char *symname(struct ksyms *ksyms, uint64_t pc, char *buf, size_t n)
{
	const struct ksym *ksym = ksyms__map_addr(ksyms, pc);

	if (!ksym)
		return "Unknown";
	snprintf(buf, n, "%s+0x%lx", ksym->name, pc - ksym->addr);
	return buf;
}

static char *print_caller(char *buf, int size, struct stack_stat *ss)
{
	snprintf(buf, size, "%u  %16s", ss->stack_id, ss->ls.acq_max_comm);
	return buf;
}

static char *print_time(char *buf, int size, uint64_t nsec)
{
	struct {
		float base;
		char *unit;
	} table[] = {
		{ 1e9 * 3600, "h " },
		{ 1e9 * 60, "m " },
		{ 1e9, "s " },
		{ 1e6, "ms" },
		{ 1e3, "us" },
		{ 0, NULL },
	};

	for (int i = 0; table[i].base; i++) {
		if (nsec < table[i].base)
			continue;

		snprintf(buf, size, "%.1f %s", nsec / table[i].base, table[i].unit);
		return buf;
	}

	snprintf(buf, size, "%u ns", (unsigned)nsec);
	return buf;
}

static void print_acq_header(void)
{
	if (env.per_thread)
		printf("\n%10s %16s", "TID", "COMM");
	else
		printf("\n%45s", "Caller");

	printf(" %9s %8s %10s %12s\n", "Avg wait", "Count", "Max wait", "Total Wait");
}

static void print_acq_stat(struct ksyms *ksyms, struct stack_stat *ss,
			   int nr_stack_entries)
{
	char buf[40];
	char avg[40];
	char max[40];
	char tot[40];

	printf("%45s %9s %8llu %10s %12s\n",
		symname(ksyms, ss->bt[0], buf, sizeof(buf)),
		print_time(avg, sizeof(avg), ss->ls.acq_total_time / ss->ls.acq_count),
		ss->ls.acq_count,
		print_time(max, sizeof(max), ss->ls.acq_max_time),
		print_time(tot, sizeof(tot), ss->ls.acq_total_time));
	for (int i = 1; i < nr_stack_entries; i++) {
		if (!ss->bt[i] || env.per_thread)
			break;
		printf("%45s\n", symname(ksyms, ss->bt[i], buf, sizeof(buf)));
	}

	if (nr_stack_entries > 1 && env.per_thread)
		printf("				Max PID %llu, COMM %s, Lock %s (0x%llx)\n",
			ss->ls.acq_max_id >> 32,
			ss->ls.acq_max_comm,
			get_lock_name(ksyms, ss->ls.acq_max_lock_ptr),
			ss->ls.acq_max_lock_ptr);
}

static void print_acq_task(struct stack_stat *ss)
{
	char buf[40];
	char avg[40];
	char max[40];
	char tot[40];

	printf("%28s %9s %8llu %10s %12s\n",
		print_caller(buf, sizeof(buf), ss),
		print_time(avg, sizeof(avg), ss->ls.acq_total_time / ss->ls.acq_count),
		ss->ls.acq_count,
		print_time(max, sizeof(max), ss->ls.acq_max_time),
		print_time(tot, sizeof(tot), ss->ls.acq_total_time));
}

static void print_hld_header(void)
{
	if (env.per_thread)
		printf("\n%10s %16s", "TID", "COMM");
	else
		printf("\n%45s", "Caller");

	printf(" %9s %8s %10s %12s\n", "Avg Hold", "Count", "Max Hold", "Total Hold");
}

static void print_hld_stat(struct ksyms *ksyms, struct stack_stat *ss,
			   int nr_stack_entries)
{
	char buf[40];
	char avg[40];
	char max[40];
	char tot[40];

	printf("%45s %9s %8llu %10s %12s\n",
		symname(ksyms, ss->bt[0], buf, sizeof(buf)),
		print_time(avg, sizeof(avg), ss->ls.hld_total_time / ss->ls.hld_count),
		ss->ls.hld_count,
		print_time(max, sizeof(max), ss->ls.hld_max_time),
		print_time(tot, sizeof(tot), ss->ls.hld_total_time));

	for (int i = 1; i < nr_stack_entries; i++) {
		if (!ss->bt[i] || env.per_thread)
			break;
		printf("%45s\n", symname(ksyms, ss->bt[i], buf, sizeof(buf)));
	}

	if (nr_stack_entries > 1 && !env.per_thread)
		printf("			Max PID %llu, COMM %s, Lock %s (0x%llx)\n",
			ss->ls.hld_max_id >> 32,
			ss->ls.hld_max_comm,
			get_lock_name(ksyms, ss->ls.hld_max_lock_ptr),
			ss->ls.hld_max_lock_ptr);
}

static void print_hld_task(struct stack_stat *ss)
{
	char buf[40];
	char avg[40];
	char max[40];
	char tot[40];

	printf("%28s %9s %8llu %10s %12s\n",
		print_caller(buf, sizeof(buf), ss),
		print_time(avg, sizeof(avg), ss->ls.hld_total_time / ss->ls.hld_count),
		ss->ls.hld_count,
		print_time(max, sizeof(max), ss->ls.hld_max_time),
		print_time(tot, sizeof(tot), ss->ls.hld_total_time));
}

static int print_stats(struct ksyms *ksyms, int stack_map, int stat_map)
{
	struct stack_stat **stats, *ss;
	size_t stat_idx = 0;
	size_t stats_sz = 1;
	uint32_t lookup_key = 0;
	uint32_t stack_id;
	int ret;
	int nr_stack_entries;

	stats = calloc(stats_sz, sizeof(void *));
	if (!stats) {
		warning("Out of memory\n");
		return -1;
	}

	while (!bpf_map_get_next_key(stat_map, &lookup_key, &stack_id)) {
		if (stat_idx == stats_sz) {
			stats_sz *= 2;
			stats = libbpf_reallocarray(stats, stats_sz, sizeof(void *));
			if (!stats) {
				warning("Out of memory\n");
				return -1;
			}
		}
		ss = malloc(sizeof(struct stack_stat));
		if (!ss) {
			warning("Out of memory\n");
			return -1;
		}

		lookup_key = ss->stack_id = stack_id;
		ret = bpf_map_lookup_elem(stat_map, &stack_id, &ss->ls);
		if (ret) {
			free(ss);
			continue;
		}

		if (!env.per_thread && bpf_map_lookup_elem(stack_map, &stack_id, &ss->bt)) {
			/* can still report the results without a backtrace. */
			warning("Failed to lookup stack_id %u\n", stack_id);
		}
		if (!env.per_thread && !caller_is_traced(ksyms, ss->bt[0])) {
			free(ss);
			continue;
		}
		stats[stat_idx++] = ss;
	}

	nr_stack_entries = MIN(env.nr_stack_entries, PERF_MAX_STACK_DEPTH);
	qsort(stats, stat_idx, sizeof(void *), sort_by_acq);
	for (int i = 0; i < MIN(env.nr_locks, stat_idx); i++) {
		if (i == 0 || env.nr_stack_entries > 1)
			print_acq_header();

		if (env.per_thread)
			print_acq_task(stats[i]);
		else
			print_acq_stat(ksyms, stats[i], nr_stack_entries);
	}

	qsort(stats, stat_idx, sizeof(void *), sort_by_hld);
	for (int i = 0; i < MIN(env.nr_locks, stat_idx); i++) {
		if (i == 0 || env.nr_stack_entries > 1)
			print_hld_header();

		if (env.per_thread)
			print_hld_task(stats[i]);
		else
			print_hld_stat(ksyms, stats[i], nr_stack_entries);
	}

	for (int i = 0; i < stat_idx; i++) {
		if (env.reset) {
			ss = stats[i];
			bpf_map_delete_elem(stat_map, &ss->stack_id);
		}
		free(stats[i]);
	}
	free(stats);

	return 0;
}

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			  va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void enable_fentry(struct klockstat_bpf *obj)
{
	bool debug_lock;

	bpf_program__set_autoload(obj->progs.kprobe_mutex_lock, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_lock_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_trylock, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_trylock_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_lock_interruptible, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_lock_interruptible_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_lock_killable, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_lock_killable_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_mutex_unlock, false);

	bpf_program__set_autoload(obj->progs.kprobe_down_read, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_trylock, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_trylock_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_interruptible, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_interruptible_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_killable, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_read_killable_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_up_read, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_write, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_write_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_write_trylock, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_write_trylock_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_write_killable, false);
	bpf_program__set_autoload(obj->progs.kprobe_down_write_killable_exit, false);
	bpf_program__set_autoload(obj->progs.kprobe_up_write, false);

	/**
	 * commit 31784cff7ee0 ("rwsem: Implement down_read_interruptible")
	 */
	if (!fentry_can_attach("down_read_interruptible", NULL)) {
		bpf_program__set_autoload(obj->progs.down_read_interruptible, false);
		bpf_program__set_autoload(obj->progs.down_read_interruptible_exit, false);
	}

	/* CONFIG_DEBUG_LOCK_ALLOC is on */
	debug_lock = fentry_can_attach("mutex_lock_nested", NULL);
	if (!debug_lock)
		return;

	bpf_program__set_attach_target(obj->progs.mutex_lock, 0,
				       "mutex_lock_nested");
	bpf_program__set_attach_target(obj->progs.mutex_lock_exit, 0,
				       "mutex_lock_nested");
	bpf_program__set_attach_target(obj->progs.mutex_lock_interruptible, 0,
				       "mutex_lock_interruptible_nested");
	bpf_program__set_attach_target(obj->progs.mutex_lock_interruptible_exit, 0,
				       "mutex_lock_interruptible_nested");
	bpf_program__set_attach_target(obj->progs.mutex_lock_killable, 0,
				       "mutex_lock_killable_nested");
	bpf_program__set_attach_target(obj->progs.mutex_lock_killable_exit, 0,
				       "mutex_lock_killable_nested");

	bpf_program__set_attach_target(obj->progs.down_read, 0,
				       "down_read_nested");
	bpf_program__set_attach_target(obj->progs.down_read_exit, 0,
				       "down_read_nested");
	bpf_program__set_attach_target(obj->progs.down_read_killable, 0,
				       "down_read_killable_nested");
	bpf_program__set_attach_target(obj->progs.down_read_killable_exit, 0,
				       "down_read_killable_nested");
	bpf_program__set_attach_target(obj->progs.down_write, 0,
				       "down_write_nested");
	bpf_program__set_attach_target(obj->progs.down_write_exit, 0,
				       "down_write_nested");
	bpf_program__set_attach_target(obj->progs.down_write_killable, 0,
				       "down_write_killable_nested");
	bpf_program__set_attach_target(obj->progs.down_write_killable_exit, 0,
				       "down_write_killable_nested");
}

static void enable_kprobes(struct klockstat_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.mutex_lock, false);
	bpf_program__set_autoload(obj->progs.mutex_lock_exit, false);
	bpf_program__set_autoload(obj->progs.mutex_trylock_exit, false);
	bpf_program__set_autoload(obj->progs.mutex_lock_interruptible, false);
	bpf_program__set_autoload(obj->progs.mutex_lock_interruptible_exit, false);
	bpf_program__set_autoload(obj->progs.mutex_lock_killable, false);
	bpf_program__set_autoload(obj->progs.mutex_lock_killable_exit, false);
	bpf_program__set_autoload(obj->progs.mutex_unlock, false);

	bpf_program__set_autoload(obj->progs.down_read, false);
	bpf_program__set_autoload(obj->progs.down_read_exit, false);
	bpf_program__set_autoload(obj->progs.down_read_trylock_exit, false);
	bpf_program__set_autoload(obj->progs.down_read_interruptible, false);
	bpf_program__set_autoload(obj->progs.down_read_interruptible_exit, false);
	bpf_program__set_autoload(obj->progs.down_read_killable, false);
	bpf_program__set_autoload(obj->progs.down_read_killable_exit, false);
	bpf_program__set_autoload(obj->progs.up_read, false);
	bpf_program__set_autoload(obj->progs.down_write, false);
	bpf_program__set_autoload(obj->progs.down_write_exit, false);
	bpf_program__set_autoload(obj->progs.down_write_trylock_exit, false);
	bpf_program__set_autoload(obj->progs.down_write_killable, false);
	bpf_program__set_autoload(obj->progs.down_write_killable_exit, false);
	bpf_program__set_autoload(obj->progs.up_write, false);

	/**
	 * commit 31784cff7ee0 ("rwsem: Implement down_read_interruptible")
	 */
	if (!kprobe_exists("down_read_interruptible")) {
		bpf_program__set_autoload(obj->progs.kprobe_down_read_interruptible, false);
		bpf_program__set_autoload(obj->progs.kprobe_down_read_interruptible_exit, false);
	}
}

int main(int argc, char *argv[])
{
	static struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.args_doc = args_doc,
		.doc = argp_program_doc,
	};
	DEFINE_SKEL_OBJECT(obj);
	struct ksyms *ksyms = NULL;
	int err;
	void *lock_addr = NULL;

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	signal(SIGINT, sig_handler);
	libbpf_set_print(libbpf_print_fn);

	ksyms = ksyms__load();
	if (!ksyms) {
		warning("failed to load kallsyms\n");
		err = 1;
		goto cleanup;
	}
	if (env.lock_name) {
		lock_addr = get_lock_addr(ksyms, env.lock_name);
		if (!lock_addr) {
			warning("Failed to find lock %s\n", env.lock_name);
			err = 1;
			goto cleanup;
		}
	}

	obj = SKEL_OPEN();
	if (!obj) {
		warning("Failed to open BPF object\n");
		err = 1;
		goto cleanup;
	}

	obj->rodata->target_tgid = env.pid;
	obj->rodata->target_pid = env.tid;
	obj->rodata->target_lock = lock_addr;
	obj->rodata->per_thread = env.per_thread;

	if (fentry_can_attach("mutex_locK", NULL) ||
	    fentry_can_attach("mutex_lock_nested", NULL))
		enable_fentry(obj);
	else
		enable_kprobes(obj);

	err = SKEL_LOAD(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		goto cleanup;
	}

	err = SKEL_ATTACH(obj);
	if (err) {
		warning("Failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing mutex/sem lock events... Hit Ctrl-C to end\n");

	for (int i = 0; i < env.iterations && !exiting; i++) {
		sleep(env.interval);

		printf("\n");
		if (env.timestamp) {
			char ts[32];

			strftime_now(ts, sizeof(ts), "%H:%M:%S");
			printf("%-8s\n", ts);
		}

		if (print_stats(ksyms, bpf_map__fd(obj->maps.stack_map),
				bpf_map__fd(obj->maps.stat_map))) {
			warning("print_stats error, aborting.\n");
			break;
		}
		fflush(stdout);
	}

	printf("Exiting trace of mutex/sem locks\n");

cleanup:
	SKEL_DESTROY(obj);
	ksyms__free(ksyms);

	return err != 0;
}
