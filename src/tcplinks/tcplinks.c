// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Jackie Liu <liuyun01@kylinos.cn>

#include "commons.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "tcplinks.h"
#include "tcplinks.skel.h"
#include <arpa/inet.h>
#include <sys/param.h>
#include <ncurses.h>

#define COLOR_LIGHTBLUE		20
#define COLOR_DARKYELLOW	30

enum SORT {
	RECEIVED,
	SENT,
	PID,
};

static struct {
	bool verbose;
	bool interval;
	int count;
	int sort_by;
} env = {
	.interval = 1,
	.count = 99999999,
};

static struct {
	int max_screen_rows;
	int max_screen_cols;
	int first;
	int focus;
	WINDOW *scroll_window;

	/* cols */
	int pid_cols;
	int tx_cols;
	int rx_cols;
} windows;

const char *argp_program_version = "tcplinks 0.1";
const char *argp_program_bug_address = "Jackie Liu <liuyun01@kylinos.cn>";
const char argp_program_doc[] =
"Show the tcp link currently running on the system.\n"
"\n"
"USAGE: tcplinks [-h] [-v] [--sort all/sent/received] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    tcplinks         # tcp links, refresh every 1s\n"
"    tcplinks 5       # refresh every 5s\n"
"    tcplinks 1 10    # refresh every 1s, 10 times\n";

static struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "sort", 's', "SORT", 0, "Sort columns, default received [pid, sent, received]", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{}
};

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
		if (!strcmp(arg, "pid")) {
			env.sort_by = PID;
		} else if (!strcmp(arg, "sent")) {
			env.sort_by = SENT;
		} else if (!strcmp(arg, "received")) {
			env.sort_by = RECEIVED;
		} else {
			warning("Invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num == 0) {
			env.interval = argp_parse_long(key, arg, state);
		} else if (state->arg_num == 1) {
			env.count = argp_parse_long(key, arg, state);
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static char *port2protocol(__u16 port, char *buf)
{
	switch (port) {
	case 21:
		return strcpy(buf, "ftp");
	case 22:
		return strcpy(buf, "ssh");
	case 23:
		return strcpy(buf, "telnet");
	case 25:
		return strcpy(buf, "smtp");
	case 53:
		return strcpy(buf, "dns");
	case 67:
	case 68:
		return strcpy(buf, "dhcp");
	case 80:
		return strcpy(buf, "http");
	case 110:
		return strcpy(buf, "pop3");
	case 143:
		return strcpy(buf, "imap");
	case 161:
	case 162:
		return strcpy(buf, "snmp");
	case 443:
		return strcpy(buf, "https");
	case 587:
		return strcpy(buf, "smtp");
	case 993:
		return strcpy(buf, "imaps");
	}

	snprintf(buf, 6, "%d", port);
	return buf;
}

struct link_map {
	__u64 key;
	struct link link;
};

static int sort_column(const void *o1, const void *o2)
{
	struct link_map *l1 = (struct link_map *)o1;
	struct link_map *l2 = (struct link_map *)o2;

	switch (env.sort_by) {
	case PID:
		return l2->link.pid - l1->link.pid;
	case SENT:
		return (l2->link.sent - l2->link.prev_sent) -
			(l1->link.sent - l1->link.prev_sent);
	case RECEIVED:
	default:
		return (l2->link.received - l2->link.prev_received) -
			(l1->link.received - l1->link.prev_received);
	}
}

static bool need_refresh(struct timespec *prev_time, int period)
{
	struct timespec current_time;
	long nsec, sec;

	clock_gettime(CLOCK_MONOTONIC, &current_time);
	nsec = current_time.tv_nsec - prev_time->tv_nsec;
	sec = current_time.tv_sec - prev_time->tv_sec;
	if (nsec < 0) {
		nsec += NSEC_PER_SEC;
		sec--;
	}

	if (sec + (double)nsec / NSEC_PER_SEC > (double)period) {
		*prev_time = current_time;
		return true;
	}

	return false;
}

static bool in_range(int num, int min, int max)
{
	return num >= min && num <= max;
}

static int handle_key(int max_rows, int fd, struct link_map *links)
{
	int err;
	fd_set input_fds;
	FD_ZERO(&input_fds);
	FD_SET(STDIN_FILENO, &input_fds);
	struct timeval timeout = {
		.tv_sec = env.interval,
	};

	err = select(STDIN_FILENO + 1, &input_fds, NULL, NULL,
			&timeout);
	if (err <= 0)
		return err;

	switch (getch()) {
	case 'q':
	case 'Q':
		return 1;
	case KEY_UP:
		windows.focus--;
		if (windows.focus < 0) {
			windows.focus = 0;
			windows.first--;
			windows.first = MAX(windows.first, 0);
		}
		break;
	case KEY_DOWN:
		if (windows.focus == max_rows - 1)
			break;
		windows.focus++;
		if (windows.focus > windows.max_screen_rows - 2) {
			windows.focus = windows.max_screen_rows - 2;
			windows.first++;
			windows.first = MIN(windows.first, max_rows - windows.max_screen_rows);
		}
		break;
	case KEY_PPAGE:
		windows.first -= windows.max_screen_rows;
		windows.first = MAX(windows.first, 0);
		break;
	case KEY_NPAGE:
		if (max_rows <= windows.max_screen_rows)
			break;
		windows.first += windows.max_screen_rows;
		windows.first = MIN(windows.first, max_rows - windows.max_screen_rows);
		break;
	case ' ':
		links[windows.focus].link.mark = !links[windows.focus].link.mark;
		bpf_map_update_elem(fd, &links[windows.focus].key, &links[windows.focus].link, BPF_EXIST);
		windows.focus++;
		if (windows.focus > windows.max_screen_rows - 2) {
			windows.focus = windows.max_screen_rows - 2;
			windows.first++;
			windows.first = MIN(windows.first, max_rows - windows.max_screen_rows);
		}
		break;
	case KEY_MOUSE: {
		MEVENT event;
		if (getmouse(&event) == OK) {
			if (event.y != 0)
				break;

			if (in_range(event.x, windows.tx_cols, windows.tx_cols+12))
				env.sort_by = SENT;
			if (in_range(event.x, windows.rx_cols, windows.rx_cols+12))
				env.sort_by = RECEIVED;
			if (in_range(event.x, 0, 11))
				env.sort_by = PID;
		}
		break;
	}
	default:
		break;
	}

	return 0;
}

static void print_header(int size)
{
	int start_cols = 0;
	int color;

	color = env.sort_by == PID ? COLOR_PAIR(2) : COLOR_PAIR(1);
	attron(color | A_BOLD);
	mvprintw(0, 0, "%7s ", "PID");
	attroff(color);
	start_cols += 8;

	color = COLOR_PAIR(1);
	attron(color);
	mvprintw(0, start_cols, "%*s %*s ", size, "LocalAddress", size,
		 "RemoteAddress");
	attroff(color);
	start_cols += (size * 2 + 2);

	windows.tx_cols = start_cols;
	color = env.sort_by == SENT ? COLOR_PAIR(2) : COLOR_PAIR(1);
	attron(color);
	mvprintw(0, start_cols, "%12s ", "TX_kb");
	attroff(color);
	start_cols += 13;

	windows.rx_cols = start_cols;
	color = env.sort_by == RECEIVED ? COLOR_PAIR(2) : COLOR_PAIR(1);
	attron(color);
	mvprintw(0, start_cols, "%12s ", "RX_kb");
	attroff(color);

	start_cols += 13;
	color = COLOR_PAIR(1);
	attron(color);
	mvprintw(0, start_cols, "%s ", "COMM");
	hline(' ', windows.max_screen_cols);
	attroff(color | A_BOLD);
}

static int print_links(struct tcplinks_bpf *obj)
{
	int fd = bpf_map__fd(obj->maps.links);
	__u64 key = 0, next_key;
	int err = 0;
	static int rows;
	static struct link_map links[MAX_ENTRIES];
	static struct timespec prev_print_time;

	err = handle_key(rows, fd, links);
	if (err)
		return err;

	if (!need_refresh(&prev_print_time, env.interval))
		goto ignore_refresh_data;
	else
		memset(links, 0, MAX_ENTRIES * sizeof(struct link_map));

	rows = 0;
	while (!bpf_map_get_next_key(fd, &key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &links[rows].link);
		if (err) {
			warning("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		key = next_key;
		links[rows].key = key;

		rows++;
	}

ignore_refresh_data:
	/* focus line should be less than rows */
	if (rows)
		windows.focus = MIN(windows.focus, rows - 1);

	qsort(links, rows, sizeof(struct link_map), sort_column);
	wclear(windows.scroll_window);

	/*
	 * A port is stored in u16, so highest value is 65535, which is
	 * 5 characters long.
	 * We need one character more for ':'.
	 */
	int size = INET6_ADDRSTRLEN + 6;
	print_header(size);

	for (int i = 0; i < MIN(windows.max_screen_rows, rows); i++) {
		char saddr[INET6_ADDRSTRLEN];
		char daddr[INET6_ADDRSTRLEN];

		struct link *link = &links[i + windows.first].link;
		inet_ntop(link->family, &link->saddr, saddr, INET6_ADDRSTRLEN);
		inet_ntop(link->family, &link->daddr, daddr, INET6_ADDRSTRLEN);

		char saddr_port[size], daddr_port[size];

		char sport[5], dport[5];
		snprintf(saddr_port, size, "%s:%s", saddr, port2protocol(link->sport, sport));
		snprintf(daddr_port, size, "%s:%s", daddr, port2protocol(link->dport, dport));

		char executable_name[MAX_NAME_LENGTH];
		if (get_process_executable_name(link->pid, executable_name) < 0)
			continue;
		if (link->mark && windows.focus != i)
			attron(COLOR_PAIR(3) | A_BOLD);
		if (windows.focus == i)
			attron(COLOR_PAIR(2));
		mvprintw(i + 1, 0, "%7d %*s %*s %12.2f %12.2f %s",
				link->pid, size, saddr_port, size, daddr_port,
				(double)(link->sent - link->prev_sent) / 1024,
				(double)(link->received - link->prev_received) / 1024,
				executable_name);

		if (link->mark && windows.focus != i)
			attroff(COLOR_PAIR(3) | A_BOLD);
		if (windows.focus == i) {
			hline(' ', windows.max_screen_cols);
			attroff(COLOR_PAIR(1));
		}
	}

	wrefresh(windows.scroll_window);
	refresh();

	/* reset link sent/received */
	for (int i = 0; i < rows; i++) {
		links[i].link.prev_sent = links[i].link.sent;
		links[i].link.prev_received = links[i].link.received;
		bpf_map_update_elem(fd, &links[i].key, &links[i].link, BPF_EXIST);
	}

	return 0;
}

static void init_ncurses_windows(void)
{
	initscr();
	start_color();
	cbreak();
	noecho();
	curs_set(FALSE);
	keypad(stdscr, TRUE);
	nodelay(stdscr, TRUE);
	mousemask(BUTTON1_RELEASED, NULL);
	assume_default_colors(-1, -1);

	short fg_color, bg_color;
	pair_content(0, &fg_color, &bg_color);

	init_color(COLOR_LIGHTBLUE, 23, 596, 604);
	init_pair(1, COLOR_BLACK, COLOR_GREEN);
	init_pair(2, COLOR_BLACK, COLOR_LIGHTBLUE);
	init_pair(3, COLOR_YELLOW, bg_color);

	getmaxyx(stdscr, windows.max_screen_rows, windows.max_screen_cols);
	windows.scroll_window = newwin(windows.max_screen_rows,
				       windows.max_screen_cols, 0, 0);
	wclear(windows.scroll_window);
}

int main(int argc, char *argv[])
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct tcplinks_bpf *obj;
	static struct argp argp = {
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

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warning("Failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = tcplinks_bpf__open_opts(&open_opts);
	if (!obj) {
		warning("Failed to open BPF object\n");
		return 1;
	}

	if (probe_tp_btf("inet_sock_set_state"))
		bpf_program__set_autoload(obj->progs.inet_sock_set_state_raw, false);
	else
		bpf_program__set_autoload(obj->progs.inet_sock_set_state, false);

	err = tcplinks_bpf__load(obj);
	if (err) {
		warning("Failed to load BPF object\n");
		goto cleanup;
	}

	err = tcplinks_bpf__attach(obj);
	if (err) {
		warning("Failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, SIG_IGN);
	init_ncurses_windows();

	while (1) {
		err = print_links(obj);
		if (err)
			goto cleanup;

		if (--env.count == 0)
			goto cleanup;
	}

cleanup:
	tcplinks_bpf__destroy(obj);
	delwin(windows.scroll_window);
	/* ncurses finish */
	endwin();

	return err != 0;
}
