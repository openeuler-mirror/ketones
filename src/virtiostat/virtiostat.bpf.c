// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Based on virtiostat.py - zhenwei pi

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "virtiostat.h"

const volatile char filter_devname[CMPMAX];
const volatile bool is_filter_devname = false;
const volatile char filter_driver[CMPMAX];
const volatile bool is_filter_driver = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, virtio_stat_t);
} stats SEC(".maps");

// see linux/include/linux/scatterlist.h
static inline unsigned int __sg_flags(struct scatterlist *sg)
{
	return BPF_CORE_READ(sg, page_link) & SG_PAGE_LINK_MASK;
}

static inline struct scatterlist *sg_chain_ptr(struct scatterlist *sg)
{
	return (struct scatterlist *)(BPF_CORE_READ(sg, page_link) & ~SG_PAGE_LINK_MASK);
}

static inline bool sg_is_chain(struct scatterlist *sg)
{
	return __sg_flags(sg) & SG_CHAIN;
}

static inline bool sg_is_last(struct scatterlist *sg)
{
	return __sg_flags(sg) & SG_END;
}

static int local_strcmp(const volatile char *cs, const char *ct)
{
	int len = 0;
	unsigned char c1, c2;

	while (len++ < CMPMAX) {
		c1 = *cs++;
		c2 = *ct++;
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		if (!c1)
			break;
	}
	return 0;
}

static struct scatterlist *__sg_next(struct scatterlist *sgp)
{
	struct scatterlist sg;

	bpf_core_read(&sg, sizeof(sg), sgp);
	if (sg_is_last(&sg))
		return NULL;

	sgp++;

	bpf_core_read(&sg, sizeof(sg), sgp);
	if (sg_is_chain(&sg))
		sgp = sg_chain_ptr(&sg);

	return sgp;
}

static u64 count_len(struct scatterlist **sgs, unsigned int num)
{
	u64 length = 0;
	unsigned int i, n;
	struct scatterlist *sgp = NULL;

	for (i = 0; (i < VIRTIO_MAX_SGS) && (i < num); i++) {
		bpf_core_read(&sgp, sizeof(sgp), (sgs + i));
		for (n = 0; sgp && (n < SG_MAX); sgp = __sg_next(sgp)) {
			length += BPF_CORE_READ(sgp, length);
			n++;
		}
		/* Suggested by Yonghong Song:
		 * IndVarSimplifyPass with clang 12 may cause verifier failure:
		 *   ; for (i = 0; (i < VIRTIO_MAX_SGS) && (i < num); i++) { // Line  60
		 *   90:   15 08 15 00 00 00 00 00 if r8 == 0 goto +21
		 *   91:   bf 81 00 00 00 00 00 00 r1 = r8
		 *   92:   07 01 00 00 ff ff ff ff r1 += -1
		 *   93:   67 01 00 00 20 00 00 00 r1 <<= 32
		 *   94:   77 01 00 00 20 00 00 00 r1 >>= 32
		 *   95:   b7 02 00 00 05 00 00 00 r2 = 5
		 *   96:   2d 12 01 00 00 00 00 00 if r2 > r1 goto +1
		 *   97:   b7 08 00 00 06 00 00 00 r8 = 6
		 *   98:   b7 02 00 00 00 00 00 00 r2 = 0
		 *   99:   b7 09 00 00 00 00 00 00 r9 = 0
		 *  100:   7b 8a 68 ff 00 00 00 00 *(u64 *)(r10 - 152) = r8
		 *  101:   05 00 35 00 00 00 00 00 goto +53
		 * Note that r1 is refined by r8 is saved to stack for later use.
		 * This will give verifier u64_max loop bound and eventually cause
		 * verification failure. Workaround with the below asm code.
		 */
#if __clang_major__ >= 7
		asm volatile("" : "=r"(i) : "0"(i));
#endif
	}

	return length;
}

static int record(struct virtqueue *vq, struct scatterlist **sgs,
                  unsigned int out_sgs, unsigned int in_sgs)
{
	virtio_stat_t newvs = {0};
	virtio_stat_t *vs;
	u64 key = (u64)vq;
	u64 in_bw = 0;
	char devname[16];
	char driver[16];

	if (is_filter_devname) {
		bpf_probe_read_kernel_str(devname, sizeof(devname),
					  BPF_CORE_READ(vq, vdev, dev.kobj.name));
		if (local_strcmp(filter_devname, devname))
			return 0;
	}

	if (is_filter_driver) {
		bpf_probe_read_kernel_str(driver, sizeof(driver),
					  BPF_CORE_READ(vq, vdev, dev.driver, name));
		if (local_strcmp(filter_driver, driver))
			return 0;
	}

	/* Workaround: separate two count_len() calls, one here and the
	 * other below. Otherwise, compiler may generate some spills which
	 * harms verifier pruning. This happens in llvm12, but not llvm4.
	 * Below code works on both cases.
	 */
	if (in_sgs)
		in_bw = count_len(sgs + out_sgs, in_sgs);

	vs = bpf_map_lookup_elem(&stats, &key);
	if (!vs) {
		bpf_probe_read_kernel_str(newvs.driver, sizeof(newvs.driver),
					  BPF_CORE_READ(vq, vdev, dev.driver, name));
		bpf_probe_read_kernel_str(newvs.dev, sizeof(newvs.dev),
					  BPF_CORE_READ(vq, vdev, dev.kobj.name));
		bpf_probe_read_kernel_str(newvs.vqname, sizeof(newvs.vqname),
					  BPF_CORE_READ(vq, name));
		newvs.out_sgs = out_sgs;
		newvs.in_sgs = in_sgs;
		if (out_sgs)
			newvs.out_bw = count_len(sgs, out_sgs);
		newvs.in_bw = in_bw;
		bpf_map_update_elem(&stats, &key, &newvs, BPF_ANY);
	} else {
		vs->out_sgs += out_sgs;
		vs->in_sgs += in_sgs;
		if (out_sgs)
			vs->out_bw += count_len(sgs, out_sgs);
		vs->in_bw += in_bw;
	}

	return 0;
}

SEC("kprobe/virtqueue_add_sgs")
int BPF_KPROBE(trace_virtqueue_add_sgs, struct virtqueue *vq,
	       struct scatterlist **sgs, unsigned int out_sgs,
	       unsigned int in_sgs, void *data, gfp_t gfp)
{
	return record(vq, sgs, out_sgs, in_sgs);
}

SEC("kprobe/virtqueue_add_outbuf")
int BPF_KPROBE(trace_virtqueue_add_outbuf, struct virtqueue *vq,
	       struct scatterlist *sg, unsigned int num,
	       void *data, gfp_t gfp)
{
	return record(vq, &sg, 1, 0);
}

SEC("kprobe/virtqueue_add_inbuf")
int BPF_KPROBE(trace_virtqueue_add_inbuf, struct virtqueue *vq,
	       struct scatterlist *sg, unsigned int num,
	       void *data, gfp_t gfp)
{
	return record(vq, &sg, 0, 1);
}

SEC("kprobe/virtqueue_add_inbuf_ctx")
int BPF_KPROBE(trace_virtqueue_add_inbuf_ctx, struct virtqueue *vq,
	       struct scatterlist *sg, unsigned int num,
	       void *data, void *_ctx, gfp_t gfp)
{
	return record(vq, &sg, 0, 1);
}

char LICENSE[] SEC("license") = "GPL";
