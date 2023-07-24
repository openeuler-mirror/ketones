// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __SHMSNOOP_H
#define __SHMSNOOP_H

#define TASK_COMM_LEN	16

/*
 * shmget() shmflg values.
 */
#define IPC_CREAT	01000      /* create if key is nonexistent */
#define IPC_EXCL	02000      /* fail if key exists */
#define SHM_HUGETLB	04000      /* segment will use huge TLB pages */
#define SHM_NORESERVE	010000     /* don't check for reservations */
#define SHM_HUGE_2MB	(21 << 26)
#define SHM_HUGE_1GB	(30 << 26)
#define SHM_EXEC	0100000

/*
 * shmat() shmflg values
 */
#define SHM_RDONLY      010000  /* read-only access */
#define SHM_RND         020000  /* round attach address to SHMLBA boundary */
#define SHM_REMAP       040000  /* take-over region on attach */
#define SHM_EXEC        0100000 /* execution access */

enum {
	SYS_SHMGET,
	SYS_SHMAT,
	SYS_SHMDT,
	SYS_SHMCTL,
};

struct event {
	pid_t pid;
	pid_t tid;
	uid_t uid;
	int sys;
	unsigned long ts;
	unsigned long key;
	unsigned long size;
	unsigned long shmflg;
	unsigned long shmid;
	unsigned long cmd;
	unsigned long buf;
	unsigned long shmaddr;
	unsigned long ret;
	char comm[TASK_COMM_LEN];
};

#endif
