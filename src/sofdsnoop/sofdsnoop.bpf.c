// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "sofdsnoop.h"

#define	SCM_RIGHTS	0x01		/* rw: access rights (array of int) */

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

const volatile __u32 g_pid = 0;
const volatile __u32 g_tid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct cmsghdr *);
} detach_ptr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, int);
} sock_fd SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static void set_fd(int fd)
{
	__u64 id = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&sock_fd, &id, &fd, BPF_ANY);
}

static __always_inline int get_fd(void)
{
	int *fd;
	__u64 id = bpf_get_current_pid_tgid();

	fd = bpf_map_lookup_elem(&sock_fd, &id);

	return fd ? *fd : -1;
}

static void put_fd(void)
{
	__u64 id = bpf_get_current_pid_tgid();

	bpf_map_delete_elem(&sock_fd, &id);
}

static __always_inline int sent_1(struct pt_regs *ctx, struct val_t *val,
				  int num, void *data)
{
	val->fd_cnt = min(num, MAX_FD);

	if (bpf_probe_read_kernel(&val->fd[0], MAX_FD * sizeof(int), data))
		return -1;

	return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
				    val, sizeof(*val));
}

#define SEND_1						\
	if (sent_1(ctx, &val, num, (void *) data))	\
		return 0;				\
							\
	num -= MAX_FD;					\
	if (num < 0)					\
		return 0;				\
							\
	data += MAX_FD;

#define SEND_2   SEND_1 SEND_1
#define SEND_4   SEND_2 SEND_2
#define SEND_8   SEND_4 SEND_4
#define SEND_26  SEND_8 SEND_8 SEND_8 SEND_2

static __always_inline int send(struct pt_regs *ctx, struct cmsghdr *cmsg,
				enum action_opt action)
{
	struct val_t val = {0};
	int *data, num;
	__u64 tsp = bpf_ktime_get_ns();

	data = (void *)((char *)cmsg + sizeof(struct cmsghdr));
	num = (BPF_CORE_READ(cmsg, cmsg_len) -
		sizeof(struct cmsghdr)) / sizeof(int);

	val.id = bpf_get_current_pid_tgid();
	val.action = action;
	val.sock_fd = get_fd();
	val.ts = tsp / 1000;

	if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) != 0)
		return 0;

	SEND_26

	return 0;
}

static __always_inline bool allow_pid(__u64 id)
{
	__u32 pid = id >> 32;	// PID is higher part
	__u32 tid = id;		// Cast and get the lower part

	if (!g_pid && !g_tid)
		return 1;

	if (g_pid == pid || g_tid == tid)
		return 1;

	return 0;
}

SEC("kprobe/__scm_send")
int trace_scm_send_entry(struct pt_regs *ctx)
{
	struct cmsghdr *cmsg = NULL;
	struct msghdr *hdr = (struct msghdr *)PT_REGS_PARM2(ctx);

	if (!allow_pid(bpf_get_current_pid_tgid()))
		return 0;

	if (BPF_CORE_READ(hdr, msg_controllen) >= sizeof(struct cmsghdr))
		cmsg = BPF_CORE_READ(hdr, msg_control);

	if (!cmsg || (BPF_CORE_READ(cmsg, cmsg_type) != SCM_RIGHTS))
		return 0;

	return send(ctx, cmsg, ACTION_SEND);
}

SEC("kprobe/scm_detach_fds")
int trace_scm_detach_fds_entry(struct pt_regs *ctx)
{
	struct cmsghdr *cmsg = NULL;
	struct msghdr *hdr = (struct msghdr *)PT_REGS_PARM1(ctx);
	__u64 id = bpf_get_current_pid_tgid();

	if (!allow_pid(id))
		return 0;

	if (BPF_CORE_READ(hdr, msg_controllen) >= sizeof(struct cmsghdr))
		cmsg = BPF_CORE_READ(hdr, msg_control);

	if (!cmsg)
		return 0;

	bpf_map_update_elem(&detach_ptr, &id, &cmsg, BPF_ANY);

	return 0;
}

SEC("kretprobe/scm_detach_fds")
int trace_scm_detach_fds_return(struct pt_regs *ctx)
{
	struct cmsghdr **cmsgp;
	__u64 id = bpf_get_current_pid_tgid();

	if (!allow_pid(id))
		return 0;

	cmsgp = bpf_map_lookup_elem(&detach_ptr, &id);
	if (!cmsgp)
		return 0;

	return send(ctx, *cmsgp, ACTION_RECV);
}

SEC("kprobe")
int BPF_KPROBE(syscall__sendmsg, struct pt_regs *regs)
{
	__u64 fd = (int)PT_REGS_PARM1_CORE(regs);

	if (!allow_pid(bpf_get_current_pid_tgid()))
		return 0;

	set_fd(fd);
	return 0;
}

SEC("kretprobe")
int trace_sendmsg_return(struct pt_regs *ctx)
{
	if (!allow_pid(bpf_get_current_pid_tgid()))
		return 0;

	put_fd();
	return 0;
}

SEC("kprobe")
int BPF_KPROBE(syscall__recvmsg, struct pt_regs *regs)
{
	__u64 fd = (int)PT_REGS_PARM1_CORE(regs);

	if (!allow_pid(bpf_get_current_pid_tgid()))
		return 0;

	set_fd(fd);
	return 0;
}

SEC("kretprobe")
int trace_recvmsg_return(struct pt_regs *ctx)
{
	if (!allow_pid(bpf_get_current_pid_tgid()))
		return 0;

	put_fd();
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
