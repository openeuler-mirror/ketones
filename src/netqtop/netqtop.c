// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Author: Jackie Liu <liuyun01@kylinos.cn>
 */
#include "commons.h"
#include "netqtop.h"
#include "netqtop.skel.h"
#include "btf_helpers.h"

#include <dirent.h>
#include <stdio.h>

#define MAX_DEVNAME_LEN	128

static volatile sig_atomic_t exiting;
static struct env {
	bool verbose;
	int interval;
	const char *name;
	bool throughput;
} env = {
	.interval = 99999999,
};

const char *argp_program_version = "netqtop 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"\nnetqtop traces the kernel functions performing packet transmit (xmit_one)\n"
"and packet receive (__netif_receive_skb_core) on data link layer. The tool\n"
"not only traces every packet via a specified network interface, but also\n"
"accounts the PPS, BPS and average size of packets as well as packet amounts\n"
"(categorized by size range) on sending and receiving direction respectively.\n"
"Results are printed as tables, which can be used to understand traffic\n"
"load allocation on each queue of interested network interface to see if it\n"
"is balanced. And the overall performance is provided in the buttom.\n"
"\n"
"Example:\n"
"    netqtop [--name] [--interval INTERVAL] [--throughout] [-n] [-i INTERVAL]\n"
"            [-t]\n";

static const struct argp_option opts[] = {
	{ "version", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "name", 'n', "DEVNAME", 0, "Trace DEVNAME only", 0 },
	{ "interval", 'i', "INTERVAL", 0, "Output interval, in seconds", 0 },
	{ "throughput", 't', NULL, 0, "Show throughput", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show this help", 0 },
	{},
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
	case 't':
		env.throughput = true;
		break;
	case 'n':
		env.name = arg;
		break;
	case 'i':
		env.interval = argp_parse_long(key, arg, state);
		break;
	case ARGP_KEY_END:
		if (!env.name) {
			warning("Please specify a network interface.\n");
			argp_usage(state);
		}
		if (strlen(env.name) > IFNAMSIZ - 1) {
			warning("NIC name too long\n");
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

static void sig_handler(int sig)
{
	exiting = true;
}

#define MAX_PATH_LEN	1024

static int prep_interface_info(int *tx_num, int *rx_num)
{
	char path[MAX_PATH_LEN];
	DIR *dir;
	struct dirent *entry;

	snprintf(path, MAX_PATH_LEN, "/sys/class/net/%s/queues", env.name);
	if (access(path, R_OK) != 0) {
		warning("Net interface %s does not exits.\n", env.name);
		return -1;
	}

	if ((dir = opendir(path)) == NULL) {
		warning("Error opening directory\n");
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type == DT_DIR) {
		       if (entry->d_name[0] == 'r')
				(*rx_num)++;
		       else if (entry->d_name[0] == 't')
				(*tx_num)++;
		}
	}

	closedir(dir);

	if (*rx_num > MAX_QUEUE_NUM || *tx_num > MAX_QUEUE_NUM) {
		warning("number of queues over 1024 is not supported.\n");
		return -1;
	}

	return 0;
}

static void print_value(double num, int column_width)
{
	char buf[128];

	if (num > 1000000) {
		snprintf(buf, ARRAY_SIZE(buf), "%.2fM", num / (1024 * 1024.0));
		printf("%-*s", column_width, buf);
	} else if (num > 1000) {
		snprintf(buf, ARRAY_SIZE(buf), "%.2fK", num / 1024.0);
		printf("%-*s", column_width, buf);
	} else {
		if (num == (int)num)
			printf("%-*d", column_width, (int)num);
		else
			printf("%-*.2f", column_width, num);
	}
}

#define PRINT_COLUMN_WIDTH	11

static void print_table(int fd)
{
	__u16 lookup_key = -1, next_key;
	struct queue_data data, total_data = {};

	printf("%-11s%-11s%-11s%-11s%-11s%-11s%-11s",
	       "QueueID", "avg_size", "[0-64)", "[64-512)",
	       "[512-2K)", "[2K-16K)", "[16K-64K)");
	if (env.throughput)
		printf("%-11s%-11s", "BPS", "PPS");
	printf("\n");

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		int err = bpf_map_lookup_elem(fd, &next_key, &data);

		if (err < 0) {
			warning("Failed to lookup info: %d\n", err);
			goto cleanup;
		}

		printf("%-11d", next_key);
		print_value(data.num_pkt ? data.total_pkt_len / data.num_pkt : 0, PRINT_COLUMN_WIDTH);
		print_value(data.size_64B, PRINT_COLUMN_WIDTH);
		print_value(data.size_512B, PRINT_COLUMN_WIDTH);
		print_value(data.size_2K, PRINT_COLUMN_WIDTH);
		print_value(data.size_16K, PRINT_COLUMN_WIDTH);
		print_value(data.size_64K, PRINT_COLUMN_WIDTH);

		total_data.total_pkt_len += data.total_pkt_len;
		total_data.num_pkt += data.num_pkt;
		total_data.size_64B += data.size_64B;
		total_data.size_512B += data.size_512B;
		total_data.size_2K += data.size_2K;
		total_data.size_16K += data.size_16K;
		total_data.size_64K += data.size_64K;

		if (env.throughput) {
			print_value(data.total_pkt_len / env.interval, PRINT_COLUMN_WIDTH);
			print_value(data.num_pkt / env.interval, PRINT_COLUMN_WIDTH);
		}
		printf("\n");

		lookup_key = next_key;
	}

	printf("%-11s", "Total");
	print_value(total_data.num_pkt ? total_data.total_pkt_len / total_data.num_pkt : 0, PRINT_COLUMN_WIDTH);
	print_value(total_data.size_64B, PRINT_COLUMN_WIDTH);
	print_value(total_data.size_512B, PRINT_COLUMN_WIDTH);
	print_value(total_data.size_2K, PRINT_COLUMN_WIDTH);
	print_value(total_data.size_16K, PRINT_COLUMN_WIDTH);
	print_value(total_data.size_64K, PRINT_COLUMN_WIDTH);

	if (env.throughput) {
		print_value(total_data.total_pkt_len / env.interval, PRINT_COLUMN_WIDTH);
		print_value(total_data.num_pkt / env.interval, PRINT_COLUMN_WIDTH);
	}
	printf("\n");

cleanup:
	lookup_key = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		bpf_map_delete_elem(fd, &next_key);
		lookup_key = next_key;
	}
}

static int print_maps(struct netqtop_bpf *obj)
{
	char ts[100];

	while (!exiting) {
		sleep(env.interval);

		/* print localtime */
		strftime_now(ts, sizeof(ts), "%a %b %d %H:%M:%S %Y");
		printf("%s\n", ts);

		/* print TX map */
		printf("TX\n");
		print_table(bpf_map__fd(obj->maps.tx_q));

		/* print RX map */
		printf("\nRX\n");
		print_table(bpf_map__fd(obj->maps.rx_q));

		for (int i = 0; i < (env.throughput ? 97 : 75); i++)
			printf("-");
		printf("\n");
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
	struct netqtop_bpf *obj;
	int err, tx_num = 0, rx_num = 0, zero = 0;
	union name_buf buf;
	int name_fd;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!bpf_is_root())
		return 1;

	if (prep_interface_info(&tx_num, &rx_num) != 0)
		return 1;

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return err;
	}

	libbpf_set_print(libbpf_print_fn);
	obj = netqtop_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		goto cleanup;
	}

	err = netqtop_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = netqtop_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		err = 1;
		warning("Failed to set signal handler\n");
		goto cleanup;
	}

	/* store interface name */
	strncpy(buf.name, env.name, IFNAMSIZ);
	name_fd = bpf_map__fd(obj->maps.name_map);
	bpf_map_update_elem(name_fd, &zero, &buf, BPF_ANY);

	err = print_maps(obj);

cleanup:
	netqtop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
