// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on dirtop.py - Erwan Velu

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "dirtop.h"
#include "maps.bpf.h"

const volatile __u32 target_tgid = 0;
const volatile __u32 inodes_number = 0;
const volatile __u32 dir_ids[MAX_DIR_NUM] = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct key_t);
	__type(value, struct val_t);
} counts SEC(".maps");

static int do_entry(void *ctx, struct file *file, char *buf, size_t count, enum op op)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct key_t info = {.inode_id = 0};
	struct dentry *pde = BPF_CORE_READ(file, f_path.dentry);
	struct val_t *valp, zero = {};

	if (target_tgid && target_tgid != tgid)
		return 0;

	for (int i = 0; i < 50; i++) {
		// If we don't have any parent, we reached the root
		if (!BPF_CORE_READ(pde, d_parent))
			break;

		pde = BPF_CORE_READ(pde, d_parent);
		// Does the files is part of the directory we look for
		for (int dir_id = 0; dir_id < inodes_number; dir_id++) {
			if (BPF_CORE_READ(pde, d_inode, i_ino) == dir_ids[dir_id]) {
				// Yes, let's export the top directory inode
				info.inode_id = BPF_CORE_READ(pde, d_inode, i_ino);
				break;
			}
		}
	}

	// If we didn't found any, let's abort
	if (info.inode_id == 0)
		return 0;

	valp = bpf_map_lookup_or_try_init(&counts, &info, &zero);
	if (valp) {
		if (op == READ) {
			valp->reads++;
			valp->rbytes += count;
		} else {
			valp->writes++;
			valp->wbytes += count;
		}
	}
	return 0;
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(trace_read_entry_kprobe, struct file *file, char *buf, size_t count)
{
	return do_entry(ctx, file, buf, count, READ);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(trace_write_entry_kprobe, struct file *file, char *buf, size_t count)
{
	return do_entry(ctx, file, buf, count, WRITE);
}

SEC("fentry/vfs_read")
int BPF_PROG(trace_read_entry_fentry, struct file *file, char *buf, size_t count)
{
	return do_entry(ctx, file, buf, count, READ);
}

SEC("fentry/vfs_write")
int BPF_PROG(trace_write_entry_fentry, struct file *file, char *buf, size_t count)
{
	return do_entry(ctx, file, buf, count, WRITE);
}

char LICENSE[] SEC("license") = "GPL";
