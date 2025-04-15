// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "commons.h"
#include "compat.h"
#include "sslsniff.h"
#include "sslsniff.skel.h"
#include <regex.h>
#include <string.h>
#include "btf_helpers.h"

#define __ATTACH_UPROBE(skel, binary_path, sym_name, prog_name, is_retprobe)	\
	do {									\
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, 			\
			.func_name = #sym_name, .retprobe = is_retprobe);	\
		skel->links.prog_name = bpf_program__attach_uprobe_opts(	\
					skel->progs.prog_name, env.pid,		\
					binary_path, 0, &uprobe_opts);		\
	} while (false)

#define __CHECK_PROGRAM(skel, prog_name)					\
	do {									\
		if (!skel->links.prog_name) {					\
			warning("no program attached for " #prog_name "\n");	\
			return -errno;						\
		}								\
	} while (false)

#define __ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name,		\
				is_retprobe)					\
	do {									\
		__ATTACH_UPROBE(skel, binary_path, sym_name, prog_name,		\
				is_retprobe);					\
		__CHECK_PROGRAM(skel, prog_name);				\
	} while (false)

#define ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name)		\
	__ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, binary_path, sym_name, prog_name)	\
	__ATTACH_UPROBE_CHECKED(skel, binary_path, sym_name, prog_name, true)

enum lib_type {
	LIB_OPENSSL,
	LIB_GNUTLS,
	LIB_NSS,
	LIB_MAX_TYPE,
};

const char *lib_name[] = {
	[LIB_OPENSSL] = "openssl",
	[LIB_GNUTLS] = "gnutls",
	[LIB_NSS] = "nss",
};

static volatile sig_atomic_t exiting;

static struct env {
	pid_t pid;
	int uid;
	bool extra;
	char *comm;
	bool openssl;
	bool gnutls;
	bool nss;
	bool latency;
	bool hexdump;
	bool handshake;
	char *extra_lib;
	bool verbose;
} env = {
	.pid = -1,
	.uid = -1,
	.openssl = true,
	.gnutls = true,
	.nss = true,
};

#define HEXDUMP_KEY 1000
#define HANDSHAKE_KEY 1002
#define EXTRA_LIB_KEY 1003

const char *argp_program_version = "sslsniff 0.1";
const char *argp_program_bug_address = "Yuan Chen <chenyuan@kylinos.cn>";
const char argp_program_doc[] =
"Sniff SSL data.\n"
"\n"
"USAGE: sslsniff [-h] [-p PID] [-u UID] [-x] [-c COMM] [-o] [-g] [-n] [-d]\n"
"		 [--hexdump] [-l] [--handshake] [--extra-lib EXTRA_LIB]\n"
"\n"
"EXAMPLES:\n"
"	./sslsniff              # sniff OpenSSL and GnuTLS functions\n"
"	./sslsniff -p 181       # sniff PID 181 only\n"
"	./sslsniff -u 1000      # sniff only UID 1000\n"
"	./sslsniff -c curl      # sniff curl command only\n"
"	./sslsniff --no-openssl # don't show OpenSSL calls\n"
"	./sslsniff --no-gnutls  # don't show GnuTLS calls\n"
"	./sslsniff --no-nss     # don't show NSS calls\n"
"	./sslsniff --hexdump    # show data as hex instead of trying to "
"decode it as UTF-8\n"
"	./sslsniff -x           # show process UID and TID\n"
"	./sslsniff -l           # show function latency\n"
"	./sslsniff -l --handshake  # show SSL handshake latency\n"
"	./sslsniff --extra-lib openssl:/path/libssl.so.1.1 # sniff extra library\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0},
	{ "pid", 'p', "PID", 0, "Sniff this PID only", 0 },
	{ "uid", 'u', "UID", 0, "Sniff this UID only", 0 },
	{ "extra", 'x', NULL, 0, "Show extra fields (UID, TID)", 0 },
	{ "comm", 'c', "COMM", 0, "Sniff only commands matching string", 0 },
	{ "no-openssl", 'o', NULL, 0, "Do not show OpenSSL calls", 0 },
	{ "no-gnutls", 'g', NULL, 0, "Do not show GnuTLS calls", 0 },
	{ "no-nss", 'n', NULL, 0, "Do not show NSS calls", 0 },
	{ "latency", 'l', NULL, 0, "Show function latency", 0 },
	{ "hexdump", HEXDUMP_KEY , NULL, 0,
	"Show data as hexdump instead of trying to decode it as UTF-8", 0 },
	{ "handshake", HANDSHAKE_KEY, NULL, 0,
	"Show SSL handshake latency, enabled only if latency option is on", 0},
	{ "extra-lib", EXTRA_LIB_KEY, "LIBTYPE:LIBPATH", 0,
	"Intercept calls from extra library", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help", 0 },
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		env.pid = argp_parse_pid(key, arg, state);
		break;
	case 'u':
		env.uid = argp_parse_long(key, arg, state);
		break;
	case 'x':
		env.extra = true;
		break;
	case 'c':
		env.comm = strdup(arg);
		break;
	case 'o':
		env.openssl = false;
		break;
	case 'g':
		env.gnutls = false;
		break;
	case 'n':
		env.nss = false;
		break;
	case 'l':
		env.latency = true;
		break;
	case HEXDUMP_KEY:
		env.hexdump = true;
		break;
	case HANDSHAKE_KEY:
		env.handshake = true;
		break;
	case EXTRA_LIB_KEY:
		env.extra_lib = strdup(arg);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static char *find_library_path(const char *libname)
{
	char cmd[128] = {0};
	static char path[512] = {0};
	char *ptr = NULL;
	char *tmp = NULL;
	FILE *fp = NULL;

	snprintf(cmd, sizeof(cmd), "ldconfig -p | grep %s", libname);
	fp = popen(cmd, "r");
	if (!fp) {
		warning("popen failed, cmd: %s\n", cmd);
		return NULL;
	}

	if (!fgets(path, sizeof(path), fp)) {
		warning("can't find lib: %s\n", libname);
		return NULL;
	}

	ptr = strrchr(path, '>');
	if (!ptr) {
		warning("can't find lib: %s, get path: %s\n", libname, path);
		return NULL;
	}
	ptr++;

	while (isspace(*ptr))
		ptr++;

	tmp = strrchr(ptr, '\n');
	if (tmp)
		*tmp = 0;

	return ptr;
}

static int attach_openssl(struct sslsniff_bpf *skel, const char *lib)
{
	ATTACH_UPROBE_CHECKED(skel, lib, SSL_write, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, SSL_write, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, SSL_read, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, SSL_read, probe_SSL_read_exit);

	if (env.latency && env.handshake) {
		ATTACH_UPROBE_CHECKED(skel, lib, SSL_do_handshake,
				      probe_SSL_do_handshake_enter);
		ATTACH_URETPROBE_CHECKED(skel, lib, SSL_do_handshake,
					 probe_SSL_do_handshake_exit);
	}

	return 0;
}

static int attach_gnutls(struct sslsniff_bpf *skel, const char *lib)
{
	ATTACH_UPROBE_CHECKED(skel, lib, gnutls_record_send, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, gnutls_record_send, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, gnutls_record_recv, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, gnutls_record_recv, probe_SSL_read_exit);

	return 0;
}

static int attach_nss(struct sslsniff_bpf *skel, const char *lib)
{
	ATTACH_UPROBE_CHECKED(skel, lib, PR_Write, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, PR_Write, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, PR_Send, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, PR_Send, probe_SSL_write_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, PR_Read, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, PR_Read, probe_SSL_read_exit);
	ATTACH_UPROBE_CHECKED(skel, lib, PR_Recv, probe_SSL_rw_enter);
	ATTACH_URETPROBE_CHECKED(skel, lib, PR_Recv, probe_SSL_read_exit);

	return 0;
}

bool ssllib_type(const char *input_str, enum lib_type *type, char *lib_path,
		 size_t lib_path_size)
{
	char lib_type_temp[10] = {0};
	char lib_path_temp[256] = {0};
	int i;

	sscanf(input_str, "%9[^:]:%255s", lib_type_temp, lib_path_temp);
	if (lib_type_temp[0] == '\0' || lib_path_temp[0] == '\0') {
		warning("Invalid SSL library param: %s\n", input_str);
		return false;
	}

	for (i = 0; i < LIB_MAX_TYPE; i++) {
		if (!strcmp(lib_type_temp, lib_name[i])) {
			*type = i;
			break;
		}
	}

	if (i >= LIB_MAX_TYPE) {
		warning("Invalid SSL library type: %s\n", lib_type_temp);
		return false;
	}

	if (access(lib_path_temp, R_OK)) {
		warning("Invalid library path: %s\n", lib_path_temp);
		return false;
	}

	strncpy(lib_path, lib_path_temp, lib_path_size);

	return true;
}

static int attach_progs(struct sslsniff_bpf *obj)
{
	enum lib_type type = LIB_MAX_TYPE;
	char lib_path[256] = {0};

	if (env.openssl)
		attach_openssl(obj, find_library_path("libssl.so"));

	if (env.gnutls)
		attach_gnutls(obj, find_library_path("libgnutls.so"));

	if (env.nss)
		attach_nss(obj, find_library_path("libnspr4.so"));

	if (!env.extra_lib)
		return 0;

	if (!ssllib_type(env.extra_lib, &type, lib_path, sizeof(lib_path))) {
		warning("Failed to parse extra library option: %s\n", env.extra_lib);
		return -1;
	}

	switch (type) {
	case LIB_OPENSSL:
		attach_openssl(obj, lib_path);
		break;
	case LIB_GNUTLS:
		attach_gnutls(obj, lib_path);
		break;
	case LIB_NSS:
		attach_nss(obj, lib_path);
		break;
	default:
		warning("Unknown library type\n");
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

static void buf_to_hex(const uint8_t *buf, size_t len, char *hex_str)
{
	for (size_t i = 0; i < len; i++)
		sprintf(hex_str + 2 * i, "%02x", buf[i]);
}

static void print_header(void)
{
	printf("%-12s %-18s %-16s %-7s %-7s", "FUNC", "TIME(s)", "COMM", "PID",
			"LEN");
	if (env.extra)
		printf(" %-7s %-7s", "UID", "TID");

	if (env.latency)
		printf(" %-7s", "LAT(ms)");

	printf("\n");
}

static void print_event(struct probe_SSL_data_t *event, const char *evt)
{
	char buf[MAX_BUF_SIZE + 1] = {0};
	unsigned int buf_size = MAX_BUF_SIZE;
	double delta = time_since_start();

	if (env.comm && strcmp(env.comm, event->comm))
		return;

	if (event->len <= MAX_BUF_SIZE)
		buf_size = event->len;

	if (event->buf_filled == 1)
		memcpy(buf, event->buf, buf_size);
	else
		buf_size = 0;

	char lat_str[10];
	if (event->delta_ns)
		snprintf(lat_str, sizeof(lat_str), "%.3f",
			(double)(event->delta_ns) / 1000000);
	else
		strncpy(lat_str, "N/A", sizeof(lat_str));

	char s_mark[] = "----- DATA -----";
	char e_mark[64] = "----- END DATA -----";
	if (buf_size < event->len)
		snprintf(e_mark, sizeof(e_mark),
			"----- END DATA (TRUNCATED, %d bytes lost) -----",
			event->len - buf_size);

	char *rw_event[] = {
		"READ/RECV",
		"WRITE/SEND",
		"HANDSHAKE"
	};

#define BASE_FMT "%-12s %-18.9f %-16s %-7d %-6d"
#define EXTRA_FMT " %-7d %-7d"
#define LATENCY_FMT " %6s"

	if (env.extra && env.latency)
		printf(BASE_FMT EXTRA_FMT LATENCY_FMT, rw_event[event->rw],
			delta, event->comm, event->pid,
			event->len, event->uid, event->tid, lat_str);
	else if (env.extra)
		printf(BASE_FMT EXTRA_FMT, rw_event[event->rw], delta, event->comm,
			event->pid, event->len, event->uid, event->tid);
	else if (env.latency)
		printf(BASE_FMT LATENCY_FMT, rw_event[event->rw], delta, event->comm,
			event->pid, event->len, lat_str);
	else
		printf(BASE_FMT, rw_event[event->rw], delta, event->comm, event->pid,
			event->len);
	printf("\n");

	if (!buf_size)
		return;

	if (!env.hexdump) {
		printf("%s\n%s\n%s\n\n\n", s_mark, buf, e_mark);
		return;
	}

	// 2 characters for each byte + null terminator
	char hex_data[MAX_BUF_SIZE * 2 + 1] = {0};
	buf_to_hex((uint8_t *)buf, buf_size, hex_data);

	printf("%s\n", s_mark);
	for (size_t i = 0; i < strlen(hex_data); i += 32)
		printf("%.32s\n", hex_data + i);
	printf("%s\n\n\n", e_mark);
}

static int handle_event(void *ctx, void *data, size_t data_size)
{
	struct probe_SSL_data_t *e = data;

	if (e->is_handshake)
		print_event(e, "perf_SSL_do_handshake");
	else
		print_event(e, "perf_SSL_rw");

	return 0;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warning("Lost %llu events on cpu #%d!\n", lost_cnt, cpu);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_buffer *buf = NULL;
	DEFINE_SKEL_OBJECT(obj);
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

	obj = SKEL_OPEN_OPTS(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	buf = bpf_buffer__new(obj->maps.events, obj->maps.heap);
	if (!buf) {
		err = 1;
		warning("Failed to create create/perf buffer");
		goto cleanup;
	}

	obj->rodata->target_pid = env.pid;
	obj->rodata->target_uid = env.uid;

	err = SKEL_LOAD(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = attach_progs(obj);
	if (err) {
		warning("Failed to attch BPF kprobe programs\n");
		goto cleanup;
	}

	err = bpf_buffer__open(buf, handle_event, handle_lost_events, NULL);
	if (err) {
		warning("Failed to open ring/perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		warning("Can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	print_header();
	while (!exiting) {
		err = bpf_buffer__poll(buf, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warning("Error polling ring/perf buffer: %d\n", err);
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	bpf_buffer__free(buf);
	SKEL_DESTROY(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
