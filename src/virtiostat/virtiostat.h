// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on virtiostat.py - zhenwei pi

#ifndef __VIRTIOSTAT_H
#define __VIRTIOSTAT_H

/* typically virtio scsi has max SGs of 6 */
#define VIRTIO_MAX_SGS		6
/* typically virtio blk has max SEG of 128 */
#define SG_MAX			128
#define MAX_NAME_LEN		16
#define SG_CHAIN		0x01UL
#define SG_END			0x02UL
#define SG_PAGE_LINK_MASK	(SG_CHAIN | SG_END)

typedef struct virtio_stat {
	char driver[16];
	char dev[12];
	char vqname[12];
	__u32 in_sgs;
	__u32 out_sgs;
	__u64 in_bw;
	__u64 out_bw;
} virtio_stat_t;

#endif
