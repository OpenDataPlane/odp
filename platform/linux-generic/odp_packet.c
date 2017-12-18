/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp/api/plat/packet_inlines.h>
#include <odp/api/packet.h>
#include <odp_packet_internal.h>
#include <odp_debug_internal.h>
#include <odp_pool_internal.h>
#include <odp/api/hints.h>
#include <odp/api/byteorder.h>

#include <protocols/eth.h>
#include <protocols/ip.h>
#include <protocols/tcp.h>
#include <protocols/udp.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include <odp/visibility_begin.h>

/* Fill in packet header field offsets for inline functions */
const _odp_packet_inline_offset_t _odp_packet_inline ODP_ALIGNED_CACHE = {
	.buf_start      = offsetof(odp_packet_hdr_t, buf_hdr.buf_start),
	.seg_len        = offsetof(odp_packet_hdr_t, buf_hdr.size),
	.frame_len      = offsetof(odp_packet_hdr_t, frame_len),
	.headroom       = offsetof(odp_packet_hdr_t, headroom),
	.tailroom       = offsetof(odp_packet_hdr_t, tailroom),
	.pool           = offsetof(odp_packet_hdr_t, buf_hdr.pool_hdl),
	.input          = offsetof(odp_packet_hdr_t, input),
	.segcount       = offsetof(odp_packet_hdr_t, buf_hdr.segcount),
	.user_ptr       = offsetof(odp_packet_hdr_t, buf_hdr.buf_ctx),
	.user_area      = offsetof(odp_packet_hdr_t, buf_hdr.uarea_addr),
	.flow_hash      = offsetof(odp_packet_hdr_t, flow_hash),
	.timestamp      = offsetof(odp_packet_hdr_t, timestamp),
	.input_flags    = offsetof(odp_packet_hdr_t, p.input_flags)
};

#include <odp/visibility_end.h>

static odp_packet_hdr_t *buf_to_packet_hdr(odp_buffer_t buf)
{
	return (odp_packet_hdr_t *)buf_hdl_to_hdr(buf);
}

void packet_parse_reset(odp_packet_hdr_t *pkt_hdr)
{
	/* Reset parser metadata before new parse */
	pkt_hdr->p.error_flags.all  = 0;
	pkt_hdr->p.input_flags.all  = 0;
	pkt_hdr->p.output_flags.all = 0;
	pkt_hdr->p.l2_offset        = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->p.l3_offset        = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->p.l4_offset        = ODP_PACKET_OFFSET_INVALID;
}

/* Calculate number of segments required for a packet of len 'seg_len' bytes. */
static inline int num_segments(uint32_t len, uint32_t seg_len)
{
	int num;

	if (CONFIG_PACKET_SEG_DISABLED)
		return 1;

	num = 1;

	if (odp_unlikely(len > seg_len)) {
		num = len / seg_len;

		if (odp_likely((num * seg_len) != len))
			num += 1;
	}

	return num;
}

/* Returns a pointer to the Nth (0-based) segment */
static odp_packet_hdr_t *get_seg(odp_packet_hdr_t *pkt_hdr, uint32_t n)
{
	uint16_t segcount = pkt_hdr->buf_hdr.segcount;

	ODP_ASSERT(n < segcount);

	if (odp_likely(CONFIG_PACKET_MAX_SEGS == 1 || segcount == 1))
		return pkt_hdr;

	while (n--) {
		ODP_ASSERT(pkt_hdr->buf_hdr.next_seg);
		pkt_hdr = pkt_hdr->buf_hdr.next_seg;
	}

	return pkt_hdr;
}

/*
 * Returns a pointer to the segment containing byte 'offset' as well as
 * the number of segments and bytes skipped to get to the segment.
 */
static odp_packet_hdr_t *get_seg_at_offset(odp_packet_hdr_t *pkt_hdr,
					   uint32_t offset,
					   uint32_t *bytes_skipped,
					   uint32_t *segs_skipped)
{
	uint32_t skipped_bytes = 0;
	uint32_t skipped_segs = 0;

	ODP_ASSERT(offset < pkt_hdr->frame_len);

	if (odp_unlikely(pkt_hdr->buf_hdr.segcount > 1)) {
		while (offset >= pkt_hdr->buf_hdr.size) {
			skipped_bytes += pkt_hdr->buf_hdr.size;
			skipped_segs++;

			offset -= pkt_hdr->buf_hdr.size;
			pkt_hdr = pkt_hdr->buf_hdr.next_seg;
			ODP_ASSERT(pkt_hdr);
		}
	}

	if (bytes_skipped)
		*bytes_skipped = skipped_bytes;
	if (segs_skipped)
		*segs_skipped = skipped_segs;

	return pkt_hdr;
}

/* Link two segment chains together. Adjusts segcounts. */
static void concat_seg(odp_packet_hdr_t *seg_a, odp_packet_hdr_t *seg_b)
{
	odp_packet_hdr_t *seg_a_last = packet_last_seg(seg_a);

	ODP_ASSERT(seg_a_last->buf_hdr.next_seg == NULL);
	seg_a_last->buf_hdr.next_seg = seg_b;

	ODP_ASSERT(seg_a->buf_hdr.segcount > 0);
	ODP_ASSERT(seg_b->buf_hdr.segcount > 0);

	seg_a->buf_hdr.segcount += seg_b->buf_hdr.segcount;
	seg_b->buf_hdr.segcount = 0;
}

/*
 * Returns a pointer to start of packet + 'offset' bytes and stores
 * the remaining length of the resulting segment in 'seg_len' and the
 * segment index in 'seg_idx'.
 */
static void *packet_map(odp_packet_hdr_t *pkt_hdr, uint32_t offset,
			uint32_t *seg_len, int *seg_idx)
{
	uint32_t skipped_segs = 0;

	if (odp_unlikely(offset >= pkt_hdr->frame_len))
		return NULL;

	if (odp_unlikely(pkt_hdr->buf_hdr.segcount > 1)) {
		while (offset >= pkt_hdr->buf_hdr.size) {
			skipped_segs++;

			offset -= pkt_hdr->buf_hdr.size;
			pkt_hdr = pkt_hdr->buf_hdr.next_seg;
		}
	}

	if (seg_len)
		*seg_len = pkt_hdr->buf_hdr.size - offset;
	if (seg_idx)
		*seg_idx = skipped_segs;

	return packet_base_data(pkt_hdr) + offset;
}

static void buffer_ref_inc(odp_buffer_hdr_t *buf_hdr)
{
	odp_atomic_inc_u32(&buf_hdr->ref_cnt);
}

static uint32_t buffer_ref_dec(odp_buffer_hdr_t *buf_hdr)
{
	return odp_atomic_fetch_dec_u32(&buf_hdr->ref_cnt);
}

static uint32_t buffer_ref(odp_buffer_hdr_t *buf_hdr)
{
	return odp_atomic_load_u32(&buf_hdr->ref_cnt);
}

static int is_multi_ref(uint32_t ref_cnt)
{
	return ref_cnt > 0;
}

static void packet_ref_inc(odp_packet_hdr_t *pkt_hdr)
{
	while (pkt_hdr) {
		buffer_ref_inc(&pkt_hdr->buf_hdr);
		pkt_hdr = pkt_hdr->buf_hdr.next_seg;
	}
}

/* Allocate 'num_pkt' packets of length 'len' bytes */
static int packet_alloc(pool_t *pool, uint32_t len, int num_pkt,
			odp_packet_t *pkts)
{
	int segs_per_pkt = num_segments(len, pool->seg_len);
	int num_buf = num_pkt * segs_per_pkt;
	odp_packet_hdr_t *pkt_hdr[num_buf];
	int npkt = num_pkt;
	int nbuf;

	ODP_ASSERT(segs_per_pkt <= CONFIG_PACKET_MAX_SEGS);

	nbuf = buffer_alloc_multi(pool, (odp_buffer_hdr_t **)pkt_hdr, num_buf);

	/* If we did not get the total number of buffers we asked for, free any
	 * buffers near the end of the list that cannot be used to make a
	 * whole packet. */
	if (odp_unlikely(nbuf != num_buf)) {
		int nfree;

		npkt = nbuf / segs_per_pkt;
		nfree = nbuf - (npkt * segs_per_pkt);

		if (nfree > 0) {
			odp_buffer_hdr_t **p =
				(odp_buffer_hdr_t **)&pkt_hdr[nbuf - nfree];
			buffer_free_multi(p, nfree);
		}
	}

	for (int i = 0; i < npkt; i++) {
		int seg = i * segs_per_pkt;

		packet_init_segs(&pkt_hdr[seg], segs_per_pkt);
		packet_init(pkt_hdr[seg], len);
		pkts[i] = (odp_packet_t)pkt_hdr[seg];
	}

	return npkt;
}

int packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len, odp_packet_t pkt[],
		       int max_num)
{
	return packet_alloc(pool_entry_from_hdl(pool_hdl),
			    len, max_num, pkt);
}

/* Free 'num' segments starting from segment 'n'. */
static void packet_free_segs(odp_packet_hdr_t *pkt, uint32_t num, uint32_t n)
{
	odp_packet_hdr_t *pkt_hdr[num];

	ODP_ASSERT(n < pkt->buf_hdr.segcount);
	ODP_ASSERT(n + num <= pkt->buf_hdr.segcount);

	pkt = get_seg(pkt, n);
	for (unsigned i = 0; i < num; i++) {
		pkt_hdr[i] = pkt;
		pkt = pkt->buf_hdr.next_seg;
	}

	buffer_free_multi((odp_buffer_hdr_t **)&pkt_hdr, num);
}

static void packet_free(odp_packet_hdr_t *pkt_hdr)
{
	int segcount = pkt_hdr->buf_hdr.segcount;
	uint32_t ref_cnt;

	ODP_ASSERT(segcount > 0);

	if (odp_likely(segcount == 1)) {
		ref_cnt = buffer_ref((odp_buffer_hdr_t *)pkt_hdr);

		if (odp_unlikely(ref_cnt)) {
			ref_cnt = buffer_ref_dec((odp_buffer_hdr_t *)pkt_hdr);

			if (is_multi_ref(ref_cnt))
				return;
		}

		buffer_free_multi((odp_buffer_hdr_t **)&pkt_hdr, 1);
	} else {
		odp_packet_hdr_t *hdr[segcount];
		int num_ref = 0;

		for (int i = 0; i < segcount; i++) {
			ref_cnt = buffer_ref((odp_buffer_hdr_t *)pkt_hdr);

			if (odp_unlikely(ref_cnt)) {
				ref_cnt = buffer_ref_dec(
					(odp_buffer_hdr_t *)pkt_hdr);

				if (is_multi_ref(ref_cnt)) {
					num_ref++;

					pkt_hdr = pkt_hdr->buf_hdr.next_seg;
					continue;
				}
			}

			hdr[i - num_ref] = pkt_hdr;

			pkt_hdr = pkt_hdr->buf_hdr.next_seg;
		}
		ODP_ASSERT(pkt_hdr == NULL);

		if (segcount - num_ref)
			buffer_free_multi((odp_buffer_hdr_t **)&hdr,
					  segcount - num_ref);
	}
}

odp_packet_t odp_packet_alloc(odp_pool_t pool_hdl, uint32_t len)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);
	odp_packet_t pkt;
	int num;

	if (odp_unlikely(pool->params.type != ODP_POOL_PACKET)) {
		__odp_errno = EINVAL;
		return ODP_PACKET_INVALID;
	}

	if (odp_unlikely(len > pool->max_len))
		return ODP_PACKET_INVALID;

	num = packet_alloc(pool, len, 1, &pkt);

	if (odp_unlikely(num == 0))
		return ODP_PACKET_INVALID;

	return pkt;
}

int odp_packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
			   odp_packet_t pkt[], int max_num)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);

	if (odp_unlikely(pool->params.type != ODP_POOL_PACKET)) {
		__odp_errno = EINVAL;
		return -1;
	}

	if (odp_unlikely(len > pool->max_len))
		return -1;

	return packet_alloc(pool, len, max_num, pkt);
}

void odp_packet_free(odp_packet_t pkt)
{
	packet_free(packet_hdr(pkt));
}

void odp_packet_free_multi(const odp_packet_t pkt[], int num)
{
	for (int i = 0; i < num; i++)
		packet_free(packet_hdr(pkt[i]));
}

int odp_packet_reset(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *const pkt_hdr = packet_hdr(pkt);
	pool_t *pool = pkt_hdr->buf_hdr.pool_ptr;
	int num = pkt_hdr->buf_hdr.segcount;

	if (odp_unlikely(len > (pool->seg_len * num)))
		return -1;

	packet_init(pkt_hdr, len);

	return 0;
}

odp_packet_t odp_packet_from_event(odp_event_t ev)
{
	if (odp_unlikely(ev == ODP_EVENT_INVALID))
		return ODP_PACKET_INVALID;

	return (odp_packet_t)buf_to_packet_hdr((odp_buffer_t)ev);
}

odp_event_t odp_packet_to_event(odp_packet_t pkt)
{
	if (odp_unlikely(pkt == ODP_PACKET_INVALID))
		return ODP_EVENT_INVALID;

	return (odp_event_t)packet_hdr(pkt);
}

uint32_t odp_packet_buf_len(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	uint32_t len = 0;

	while (pkt_hdr) {
		len += packet_buf_len(pkt_hdr);
		pkt_hdr = pkt_hdr->buf_hdr.next_seg;
	}
	return len;
}

void *odp_packet_tail(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	odp_packet_hdr_t *seg = packet_last_seg(pkt_hdr);

	return seg->buf_hdr.buf_end - pkt_hdr->tailroom;
}

void *odp_packet_offset(odp_packet_t pkt, uint32_t offset, uint32_t *len,
			odp_packet_seg_t *seg)
{
	int seg_idx;
	void *addr = packet_map(
		(odp_packet_hdr_t *)(uintptr_t)pkt, offset, len, &seg_idx);

	if (addr != NULL && seg != NULL)
		*seg = _odp_packet_seg_from_ndx(seg_idx);

	return addr;
}

void *odp_packet_push_head(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (len > pkt_hdr->headroom)
		return NULL;

	pkt_hdr->buf_hdr.size += len;
	pkt_hdr->headroom -= len;
	pkt_hdr->frame_len += len;

	return packet_base_data(pkt_hdr);
}

void *odp_packet_pull_head(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (len > pkt_hdr->frame_len)
		return NULL;

	pkt_hdr->buf_hdr.size -= len;
	pkt_hdr->headroom += len;
	pkt_hdr->frame_len -= len;

	return packet_base_data(pkt_hdr);
}

void *odp_packet_push_tail(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	odp_packet_hdr_t *seg = packet_last_seg(pkt_hdr);
	void *old_tail;

	if (len > pkt_hdr->tailroom)
		return NULL;

	old_tail = seg->buf_hdr.buf_end - pkt_hdr->tailroom;

	seg->buf_hdr.size += len;
	pkt_hdr->tailroom -= len;
	pkt_hdr->frame_len += len;

	return old_tail;
}

void *odp_packet_pull_tail(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	odp_packet_hdr_t *seg = packet_last_seg(pkt_hdr);

	if (len > seg->buf_hdr.size)
		return NULL;

	seg->buf_hdr.size -= len;
	pkt_hdr->tailroom += len;
	pkt_hdr->frame_len -= len;

	return seg->buf_hdr.buf_end - pkt_hdr->tailroom;
}

/* Copy a subset of metadata fields from one packet to another. */
static void packet_copy_md(odp_packet_hdr_t *dst, odp_packet_hdr_t *src)
{
	dst->p			= src->p;
	dst->input		= src->input;
	dst->dst_queue		= src->dst_queue;
	dst->flow_hash		= src->flow_hash;
	dst->timestamp		= src->timestamp;
	dst->buf_hdr.buf_u64	= src->buf_hdr.buf_u64;
	dst->buf_hdr.uarea_addr	= src->buf_hdr.uarea_addr;
}

int odp_packet_extend_head(odp_packet_t *pkt, uint32_t len,
			   void **data_ptr, uint32_t *seg_len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(*pkt);
	int rv;

	if (len <= pkt_hdr->headroom) {
		if (odp_packet_push_head(*pkt, len) == NULL)
			return -1;

		if (data_ptr)
			*data_ptr = packet_base_data(pkt_hdr);
		if (seg_len)
			*seg_len = pkt_hdr->buf_hdr.size;

		rv = 0;
	} else {
		pool_t *pool = pkt_hdr->buf_hdr.pool_ptr;
		odp_packet_t head;
		uint16_t headroom;

		if (odp_unlikely(pkt_hdr->frame_len + len > pool->max_len))
			return -1;

		headroom = pkt_hdr->headroom;
		pkt_hdr->buf_hdr.size += headroom;
		pkt_hdr->headroom -= headroom;
		pkt_hdr->frame_len += headroom;

		if (packet_alloc(pool, len - headroom, 1, &head) != 1)
			return -1;

		concat_seg((odp_packet_hdr_t *)(uintptr_t)head, pkt_hdr);

		packet_hdr(head)->frame_len += pkt_hdr->frame_len;
		packet_hdr(head)->tailroom = pkt_hdr->tailroom;

		packet_copy_md(packet_hdr(head), pkt_hdr);

		if (data_ptr)
			*data_ptr = packet_base_data(packet_hdr(head));
		if (seg_len)
			*seg_len = packet_hdr(head)->buf_hdr.size;

		*pkt = head;

		rv = 1;
	}
	return rv;
}

int odp_packet_trunc_head(odp_packet_t *pkt, uint32_t len,
			  void **data_ptr, uint32_t *seg_len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(*pkt);
	int rv = -1;

	if (len > pkt_hdr->frame_len)
		return rv;

	if (len < pkt_hdr->buf_hdr.size) {
		if (odp_packet_pull_head(*pkt, len) == NULL)
			return -1;

		if (data_ptr)
			*data_ptr = packet_base_data(pkt_hdr);
		if (seg_len)
			*seg_len = pkt_hdr->buf_hdr.size;

		rv = 0;
	} else {
		uint32_t bytes_skipped, segs_skipped;
		odp_packet_hdr_t *head = get_seg_at_offset(pkt_hdr, len,
							   &bytes_skipped,
							   &segs_skipped);
		ODP_ASSERT(bytes_skipped > 0);
		ODP_ASSERT(segs_skipped > 0);

		packet_copy_md(head, pkt_hdr);

		head->buf_hdr.segcount =
			pkt_hdr->buf_hdr.segcount - segs_skipped;
		head->frame_len = pkt_hdr->frame_len - bytes_skipped;
		head->headroom = 0;
		head->tailroom = pkt_hdr->tailroom;

		packet_free_segs(pkt_hdr, segs_skipped, 0);

		if (odp_packet_pull_head(
			    (odp_packet_t)head, len - bytes_skipped) == NULL)
			return -1;

		if (data_ptr)
			*data_ptr = packet_base_data(head);
		if (seg_len)
			*seg_len = head->buf_hdr.size;

		*pkt = (odp_packet_t)head;

		rv = 1;
	}
	return rv;
}

int odp_packet_extend_tail(odp_packet_t *pkt, uint32_t len,
			   void **data_ptr, uint32_t *seg_len_out)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(*pkt);
	uint32_t old_frame_len = pkt_hdr->frame_len;
	uint32_t seg_len = 0;
	void *offset;

	if (len <= pkt_hdr->tailroom) {
		if (odp_packet_push_tail(*pkt, len) == NULL)
			return -1;
	} else {
		pool_t *pool = pkt_hdr->buf_hdr.pool_ptr;
		odp_packet_hdr_t *seg;
		odp_packet_t tail;

		if (odp_unlikely(pkt_hdr->frame_len + len > pool->max_len))
			return -1;

		seg = packet_last_seg(pkt_hdr);
		seg->buf_hdr.size += pkt_hdr->tailroom;

		if (packet_alloc(pool, len - pkt_hdr->tailroom, 1, &tail) != 1)
			return -1;

		concat_seg(pkt_hdr, packet_hdr(tail));

		pkt_hdr->frame_len += len;
		pkt_hdr->tailroom = packet_hdr(tail)->tailroom;
	}

	if (data_ptr || seg_len_out)
		offset = packet_map(pkt_hdr, old_frame_len, &seg_len, NULL);

	if (data_ptr)
		*data_ptr = offset;
	if (seg_len_out)
		*seg_len_out = seg_len;

	return 0;
}

int odp_packet_trunc_tail(odp_packet_t *pkt, uint32_t len,
			  void **tail_ptr, uint32_t *tailroom)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(*pkt);
	odp_packet_hdr_t *pkt_hdr_last = packet_last_seg(pkt_hdr);

	if (len <= pkt_hdr_last->buf_hdr.size) {
		if (odp_packet_pull_tail(*pkt, len) == NULL)
			return -1;
	} else {
		uint32_t bytes_skipped, segs_skipped;
		odp_packet_hdr_t *last;
		int last_size;
		int num;

		last = get_seg_at_offset(pkt_hdr, pkt_hdr->frame_len - len,
					 &bytes_skipped, &segs_skipped);

		num = pkt_hdr->buf_hdr.segcount - (segs_skipped + 1);
		packet_free_segs(pkt_hdr, num, segs_skipped + 1);

		pkt_hdr->buf_hdr.segcount -= num;
		last->buf_hdr.next_seg = NULL;

		pkt_hdr->frame_len -= len;

		last_size = pkt_hdr->frame_len - bytes_skipped;
		pkt_hdr->tailroom = last->buf_hdr.size - last_size;
		last->buf_hdr.size = last_size;
	}

	if (tail_ptr)
		*tail_ptr = odp_packet_tail(*pkt);
	if (tailroom)
		*tailroom = pkt_hdr->tailroom;

	return 0;
}

uint32_t odp_packet_user_area_size(odp_packet_t pkt)
{
	pool_t *pool = pool_entry_from_hdl(odp_packet_pool(pkt));

	return pool->params.pkt.uarea_size;
}

int odp_packet_input_index(odp_packet_t pkt)
{
	return odp_pktio_index(packet_hdr(pkt)->input);
}

void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ctx)
{
	packet_hdr(pkt)->buf_hdr.buf_cctx = ctx;
}

void *odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (!packet_hdr_has_l2(pkt_hdr))
		return NULL;
	return packet_map(pkt_hdr, pkt_hdr->p.l2_offset, len, NULL);
}

uint32_t odp_packet_l2_offset(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (!packet_hdr_has_l2(pkt_hdr))
		return ODP_PACKET_OFFSET_INVALID;
	return pkt_hdr->p.l2_offset;
}

int odp_packet_l2_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (offset >= pkt_hdr->frame_len)
		return -1;

	packet_hdr_has_l2_set(pkt_hdr, 1);
	pkt_hdr->p.l2_offset = offset;
	return 0;
}

void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	return packet_map(pkt_hdr, pkt_hdr->p.l3_offset, len, NULL);
}

uint32_t odp_packet_l3_offset(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	return pkt_hdr->p.l3_offset;
}

int odp_packet_l3_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (offset >= pkt_hdr->frame_len)
		return -1;

	pkt_hdr->p.l3_offset = offset;
	return 0;
}

void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	return packet_map(pkt_hdr, pkt_hdr->p.l4_offset, len, NULL);
}

uint32_t odp_packet_l4_offset(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	return pkt_hdr->p.l4_offset;
}

int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (offset >= pkt_hdr->frame_len)
		return -1;

	pkt_hdr->p.l4_offset = offset;
	return 0;
}

void odp_packet_flow_hash_set(odp_packet_t pkt, uint32_t flow_hash)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->flow_hash = flow_hash;
	pkt_hdr->p.input_flags.flow_hash = 1;
}

void odp_packet_ts_set(odp_packet_t pkt, odp_time_t timestamp)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->timestamp = timestamp;
	pkt_hdr->p.input_flags.timestamp = 1;
}

void *odp_packet_seg_data(odp_packet_t pkt, odp_packet_seg_t seg)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (odp_unlikely(_odp_packet_seg_to_ndx(seg) >=
			 pkt_hdr->buf_hdr.segcount))
		return NULL;

	pkt_hdr = get_seg(pkt_hdr, _odp_packet_seg_to_ndx(seg));

	return packet_base_data(pkt_hdr);
}

uint32_t odp_packet_seg_data_len(odp_packet_t pkt, odp_packet_seg_t seg)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	ODP_ASSERT(_odp_packet_seg_to_ndx(seg) < pkt_hdr->buf_hdr.segcount);

	pkt_hdr = get_seg(pkt_hdr, _odp_packet_seg_to_ndx(seg));

	return pkt_hdr->buf_hdr.size;
}

int odp_packet_add_data(odp_packet_t *pkt_ptr, uint32_t offset, uint32_t len)
{
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	uint32_t pktlen = pkt_hdr->frame_len;
	odp_packet_t newpkt;

	if (offset > pktlen)
		return -1;

	newpkt = odp_packet_alloc(pkt_hdr->buf_hdr.pool_hdl, pktlen + len);

	if (newpkt == ODP_PACKET_INVALID)
		return -1;

	if (odp_packet_copy_from_pkt(newpkt, 0, pkt, 0, offset) != 0 ||
	    odp_packet_copy_from_pkt(newpkt, offset + len, pkt, offset,
				     pktlen - offset) != 0) {
		odp_packet_free(newpkt);
		return -1;
	}

	_odp_packet_copy_md_to_packet(pkt, newpkt);
	odp_packet_free(pkt);
	*pkt_ptr = newpkt;

	return 1;
}

int odp_packet_rem_data(odp_packet_t *pkt_ptr, uint32_t offset, uint32_t len)
{
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	uint32_t pktlen = pkt_hdr->frame_len;
	odp_packet_t newpkt;

	if (offset > pktlen || offset + len > pktlen)
		return -1;

	newpkt = odp_packet_alloc(pkt_hdr->buf_hdr.pool_hdl, pktlen - len);

	if (newpkt == ODP_PACKET_INVALID)
		return -1;

	if (odp_packet_copy_from_pkt(newpkt, 0, pkt, 0, offset) != 0 ||
	    odp_packet_copy_from_pkt(newpkt, offset, pkt, offset + len,
				     pktlen - offset - len) != 0) {
		odp_packet_free(newpkt);
		return -1;
	}

	_odp_packet_copy_md_to_packet(pkt, newpkt);
	odp_packet_free(pkt);
	*pkt_ptr = newpkt;

	return 1;
}

int odp_packet_align(odp_packet_t *pkt, uint32_t offset, uint32_t len,
		     uint32_t align)
{
	int rc;
	uint32_t shift;
	uint32_t seglen = 0;  /* GCC */
	odp_packet_hdr_t *pkt_hdr = packet_hdr(*pkt);
	void *addr = packet_map(pkt_hdr, offset, &seglen, NULL);
	uint64_t uaddr = (uint64_t)(uintptr_t)addr;
	uint64_t misalign;

	if (align > ODP_CACHE_LINE_SIZE)
		return -1;

	if (seglen >= len) {
		misalign = align <= 1 ? 0 :
			ROUNDUP_ALIGN(uaddr, align) - uaddr;
		if (misalign == 0)
			return 0;
		shift = align - misalign;
	} else {
		if (len > pkt_hdr->buf_hdr.size)
			return -1;
		shift  = len - seglen;
		uaddr -= shift;
		misalign = align <= 1 ? 0 :
			ROUNDUP_ALIGN(uaddr, align) - uaddr;
		if (misalign)
			shift += align - misalign;
	}

	rc = odp_packet_extend_head(pkt, shift, NULL, NULL);
	if (rc < 0)
		return rc;

	(void)odp_packet_move_data(*pkt, 0, shift,
				   _odp_packet_len(*pkt) - shift);

	(void)odp_packet_trunc_tail(pkt, shift, NULL, NULL);
	return 1;
}

int odp_packet_concat(odp_packet_t *dst, odp_packet_t src)
{
	odp_packet_hdr_t *dst_hdr = packet_hdr(*dst);
	odp_packet_hdr_t *src_hdr = packet_hdr(src);
	pool_t *dst_pool = dst_hdr->buf_hdr.pool_ptr;
	pool_t *src_pool = src_hdr->buf_hdr.pool_ptr;
	uint32_t dst_len = dst_hdr->frame_len;
	uint32_t src_len = src_hdr->frame_len;

	/* Do a copy if packets are from different pools. */
	if (odp_unlikely(dst_pool != src_pool)) {
		if (odp_packet_extend_tail(dst, src_len, NULL, NULL) >= 0) {
			(void)odp_packet_copy_from_pkt(*dst, dst_len,
						       src, 0, src_len);
			odp_packet_free(src);

			/* Data was moved in memory */
			return 1;
		}

		return -1;
	}

	concat_seg(dst_hdr, src_hdr);

	dst_hdr->frame_len = dst_len + src_len;
	dst_hdr->tailroom  = src_hdr->tailroom;

	/* Data was not moved in memory */
	return 0;
}

int odp_packet_split(odp_packet_t *pkt, uint32_t len, odp_packet_t *tail)
{
	uint32_t pktlen = _odp_packet_len(*pkt);

	if (len >= pktlen || tail == NULL)
		return -1;

	*tail = odp_packet_copy_part(*pkt, len, pktlen - len,
				     odp_packet_pool(*pkt));

	if (*tail == ODP_PACKET_INVALID)
		return -1;

	return odp_packet_trunc_tail(pkt, pktlen - len, NULL, NULL);
}

odp_packet_t odp_packet_copy(odp_packet_t pkt, odp_pool_t pool)
{
	odp_packet_hdr_t *srchdr = packet_hdr(pkt);
	uint32_t pktlen = srchdr->frame_len;
	odp_packet_t newpkt = odp_packet_alloc(pool, pktlen);

	if (newpkt != ODP_PACKET_INVALID) {
		if (_odp_packet_copy_md_to_packet(pkt, newpkt) ||
		    odp_packet_copy_from_pkt(newpkt, 0, pkt, 0, pktlen)) {
			odp_packet_free(newpkt);
			newpkt = ODP_PACKET_INVALID;
		}
	}

	return newpkt;
}

odp_packet_t odp_packet_copy_part(odp_packet_t pkt, uint32_t offset,
				  uint32_t len, odp_pool_t pool)
{
	uint32_t pktlen = _odp_packet_len(pkt);
	odp_packet_t newpkt;

	if (offset >= pktlen || offset + len > pktlen)
		return ODP_PACKET_INVALID;

	newpkt = odp_packet_alloc(pool, len);
	if (newpkt != ODP_PACKET_INVALID)
		odp_packet_copy_from_pkt(newpkt, 0, pkt, offset, len);

	return newpkt;
}

int odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
			   uint32_t len, void *dst)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t cpylen;
	uint8_t *dstaddr = (uint8_t *)dst;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (offset + len > pkt_hdr->frame_len)
		return -1;

	while (len > 0) {
		mapaddr = packet_map(pkt_hdr, offset, &seglen, NULL);
		cpylen = len > seglen ? seglen : len;
		memcpy(dstaddr, mapaddr, cpylen);
		offset  += cpylen;
		dstaddr += cpylen;
		len     -= cpylen;
	}

	return 0;
}

int odp_packet_copy_from_mem(odp_packet_t pkt, uint32_t offset,
			     uint32_t len, const void *src)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t cpylen;
	const uint8_t *srcaddr = (const uint8_t *)src;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (offset + len > pkt_hdr->frame_len)
		return -1;

	while (len > 0) {
		mapaddr = packet_map(pkt_hdr, offset, &seglen, NULL);
		cpylen = len > seglen ? seglen : len;
		memcpy(mapaddr, srcaddr, cpylen);
		offset  += cpylen;
		srcaddr += cpylen;
		len     -= cpylen;
	}

	return 0;
}

int odp_packet_copy_from_pkt(odp_packet_t dst, uint32_t dst_offset,
			     odp_packet_t src, uint32_t src_offset,
			     uint32_t len)
{
	odp_packet_hdr_t *dst_hdr = packet_hdr(dst);
	odp_packet_hdr_t *src_hdr = packet_hdr(src);
	void *dst_map;
	void *src_map;
	uint32_t cpylen, minseg;
	uint32_t dst_seglen = 0; /* GCC */
	uint32_t src_seglen = 0; /* GCC */
	int overlap;

	if (dst_offset + len > dst_hdr->frame_len ||
	    src_offset + len > src_hdr->frame_len)
		return -1;

	overlap = (dst_hdr == src_hdr &&
		   ((dst_offset <= src_offset &&
		     dst_offset + len >= src_offset) ||
		    (src_offset <= dst_offset &&
		     src_offset + len >= dst_offset)));

	if (overlap && src_offset < dst_offset) {
		odp_packet_t temp =
			odp_packet_copy_part(src, src_offset, len,
					     odp_packet_pool(src));
		if (temp == ODP_PACKET_INVALID)
			return -1;
		odp_packet_copy_from_pkt(dst, dst_offset, temp, 0, len);
		odp_packet_free(temp);
		return 0;
	}

	while (len > 0) {
		dst_map = packet_map(dst_hdr, dst_offset, &dst_seglen, NULL);
		src_map = packet_map(src_hdr, src_offset, &src_seglen, NULL);

		minseg = dst_seglen > src_seglen ? src_seglen : dst_seglen;
		cpylen = len > minseg ? minseg : len;

		if (overlap)
			memmove(dst_map, src_map, cpylen);
		else
			memcpy(dst_map, src_map, cpylen);

		dst_offset += cpylen;
		src_offset += cpylen;
		len        -= cpylen;
	}

	return 0;
}

int odp_packet_copy_data(odp_packet_t pkt, uint32_t dst_offset,
			 uint32_t src_offset, uint32_t len)
{
	return odp_packet_copy_from_pkt(pkt, dst_offset,
					pkt, src_offset, len);
}

int odp_packet_move_data(odp_packet_t pkt, uint32_t dst_offset,
			 uint32_t src_offset, uint32_t len)
{
	return odp_packet_copy_from_pkt(pkt, dst_offset,
					pkt, src_offset, len);
}

int _odp_packet_set_data(odp_packet_t pkt, uint32_t offset,
			 uint8_t c, uint32_t len)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t setlen;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (offset + len > pkt_hdr->frame_len)
		return -1;

	while (len > 0) {
		mapaddr = packet_map(pkt_hdr, offset, &seglen, NULL);
		setlen = len > seglen ? seglen : len;
		memset(mapaddr, c, setlen);
		offset  += setlen;
		len     -= setlen;
	}

	return 0;
}

int _odp_packet_cmp_data(odp_packet_t pkt, uint32_t offset,
			 const void *s, uint32_t len)
{
	const uint8_t *ptr = s;
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t cmplen;
	int ret;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	ODP_ASSERT(offset + len <= pkt_hdr->frame_len);

	while (len > 0) {
		mapaddr = packet_map(pkt_hdr, offset, &seglen, NULL);
		cmplen = len > seglen ? seglen : len;
		ret = memcmp(mapaddr, ptr, cmplen);
		if (ret != 0)
			return ret;
		offset  += cmplen;
		len     -= cmplen;
		ptr     += cmplen;
	}

	return 0;
}

void odp_packet_print(odp_packet_t pkt)
{
	int max_len = 2048;
	char str[max_len];
	int len = 0;
	int n = max_len - 1;
	odp_packet_hdr_t *hdr = packet_hdr(pkt);
	odp_buffer_t buf      = packet_to_buffer(pkt);

	len += snprintf(&str[len], n - len, "Packet ");
	len += odp_buffer_snprint(&str[len], n - len, buf);
	len += snprintf(&str[len], n - len, "  input_flags  0x%" PRIx64 "\n",
			hdr->p.input_flags.all);
	len += snprintf(&str[len], n - len, "  error_flags  0x%" PRIx32 "\n",
			hdr->p.error_flags.all);
	len += snprintf(&str[len], n - len,
			"  output_flags 0x%" PRIx32 "\n",
			hdr->p.output_flags.all);
	len += snprintf(&str[len], n - len,
			"  uarea_addr   0x%p\n",
			hdr->buf_hdr.uarea_addr);
	len += snprintf(&str[len], n - len,
			"  l2_offset    %" PRIu32 "\n", hdr->p.l2_offset);
	len += snprintf(&str[len], n - len,
			"  l3_offset    %" PRIu32 "\n", hdr->p.l3_offset);
	len += snprintf(&str[len], n - len,
			"  l4_offset    %" PRIu32 "\n", hdr->p.l4_offset);
	len += snprintf(&str[len], n - len,
			"  input        %" PRIu64 "\n",
			odp_pktio_to_u64(hdr->input));
	len += snprintf(&str[len], n - len,
			"  frame_len    %" PRIu32 "\n", hdr->frame_len);
	len += snprintf(&str[len], n - len,
			"  headroom     %" PRIu32 "\n",
			odp_packet_headroom(pkt));
	len += snprintf(&str[len], n - len,
			"  tailroom     %" PRIu32 "\n",
			odp_packet_tailroom(pkt));
	len += snprintf(&str[len], n - len,
			"  num_segs     %i\n", odp_packet_num_segs(pkt));

	do {
		len += snprintf(&str[len], n - len,
				"    %p ref_cnt=%u size=%-5u "
				"base_data=%p buf_end=%p next_seg=%p\n",
				hdr,
				buffer_ref(&hdr->buf_hdr),
				hdr->buf_hdr.size,
				packet_base_data(hdr),
				hdr->buf_hdr.buf_end,
				hdr->buf_hdr.next_seg);

		hdr = hdr->buf_hdr.next_seg;
	} while (hdr);

	str[len] = '\0';

	ODP_PRINT("\n%s\n", str);
}

void odp_packet_print_data(odp_packet_t pkt, uint32_t offset,
			   uint32_t byte_len)
{
	odp_packet_hdr_t *hdr = packet_hdr(pkt);
	uint32_t bytes_per_row = 16;
	int num_rows = (byte_len + bytes_per_row - 1) / bytes_per_row;
	int max_len = 256 + (3 * byte_len) + (3 * num_rows);
	char str[max_len];
	int len = 0;
	int n = max_len - 1;
	uint32_t data_len = odp_packet_len(pkt);
	pool_t *pool = hdr->buf_hdr.pool_ptr;

	len += snprintf(&str[len], n - len, "Packet\n------\n");
	len += snprintf(&str[len], n - len,
			"  pool index    %" PRIu32 "\n", pool->pool_idx);
	len += snprintf(&str[len], n - len,
			"  buf index     %" PRIu32 "\n",
			buf_hdr_to_index(&hdr->buf_hdr));
	len += snprintf(&str[len], n - len,
			"  segcount      %" PRIu16 "\n", hdr->buf_hdr.segcount);
	len += snprintf(&str[len], n - len,
			"  data len      %" PRIu32 "\n", data_len);
	len += snprintf(&str[len], n - len,
			"  data ptr      %p\n", odp_packet_data(pkt));
	len += snprintf(&str[len], n - len,
			"  print offset  %" PRIu32 "\n", offset);
	len += snprintf(&str[len], n - len,
			"  print length  %" PRIu32 "\n", byte_len);

	if (offset + byte_len > data_len) {
		len += snprintf(&str[len], n - len, " BAD OFFSET OR LEN\n");
		ODP_PRINT("%s\n", str);
		return;
	}

	while (byte_len) {
		uint32_t copy_len;
		uint8_t data[bytes_per_row];
		uint32_t i;

		if (byte_len > bytes_per_row)
			copy_len = bytes_per_row;
		else
			copy_len = byte_len;

		odp_packet_copy_to_mem(pkt, offset, copy_len, data);

		len += snprintf(&str[len], n - len, " ");

		for (i = 0; i < copy_len; i++)
			len += snprintf(&str[len], n - len, " %02x", data[i]);

		len += snprintf(&str[len], n - len, "\n");

		byte_len -= copy_len;
		offset   += copy_len;
	}

	ODP_PRINT("%s\n", str);
}

int odp_packet_is_valid(odp_packet_t pkt)
{
	if (odp_buffer_is_valid(packet_to_buffer(pkt)) == 0)
		return 0;

	if (odp_event_type(odp_packet_to_event(pkt)) != ODP_EVENT_PACKET)
		return 0;

	return 1;
}

int _odp_packet_copy_md_to_packet(odp_packet_t srcpkt, odp_packet_t dstpkt)
{
	odp_packet_hdr_t *srchdr = packet_hdr(srcpkt);
	odp_packet_hdr_t *dsthdr = packet_hdr(dstpkt);
	uint32_t src_size = odp_packet_user_area_size(srcpkt);
	uint32_t dst_size = odp_packet_user_area_size(dstpkt);

	dsthdr->input = srchdr->input;
	dsthdr->dst_queue = srchdr->dst_queue;
	dsthdr->buf_hdr.buf_u64 = srchdr->buf_hdr.buf_u64;
	if (dsthdr->buf_hdr.uarea_addr != NULL &&
	    srchdr->buf_hdr.uarea_addr != NULL)
		memcpy(dsthdr->buf_hdr.uarea_addr,
		       srchdr->buf_hdr.uarea_addr,
		       dst_size <= src_size ? dst_size : src_size);

	copy_packet_parser_metadata(srchdr, dsthdr);

	/* Metadata copied, but return indication of whether the packet
	 * user area was truncated in the process. Note this can only
	 * happen when copying between different pools.
	 */
	return dst_size < src_size;
}

/** Parser helper function for Ethernet packets */
static inline uint16_t parse_eth(packet_parser_t *prs, const uint8_t **parseptr,
				 uint32_t *offset, uint32_t frame_len)
{
	uint16_t ethtype;
	const _odp_ethhdr_t *eth;
	uint16_t macaddr0, macaddr2, macaddr4;
	const _odp_vlanhdr_t *vlan;

	/* Detect jumbo frames */
	if (frame_len > _ODP_ETH_LEN_MAX)
		prs->input_flags.jumbo = 1;

	eth = (const _odp_ethhdr_t *)*parseptr;

	/* Handle Ethernet broadcast/multicast addresses */
	macaddr0 = odp_be_to_cpu_16(*((const uint16_t *)(const void *)eth));
	prs->input_flags.eth_mcast = (macaddr0 & 0x0100) == 0x0100;

	if (macaddr0 == 0xffff) {
		macaddr2 =
			odp_be_to_cpu_16(*((const uint16_t *)
					   (const void *)eth + 1));
		macaddr4 =
			odp_be_to_cpu_16(*((const uint16_t *)
					   (const void *)eth + 2));
		prs->input_flags.eth_bcast =
			(macaddr2 == 0xffff) && (macaddr4 == 0xffff);
	} else {
		prs->input_flags.eth_bcast = 0;
	}

	/* Get Ethertype */
	ethtype = odp_be_to_cpu_16(eth->type);
	*offset += sizeof(*eth);
	*parseptr += sizeof(*eth);

	/* Check for SNAP vs. DIX */
	if (ethtype < _ODP_ETH_LEN_MAX) {
		prs->input_flags.snap = 1;
		if (ethtype > frame_len - *offset) {
			prs->error_flags.snap_len = 1;
			return 0;
		}
		ethtype = odp_be_to_cpu_16(*((const uint16_t *)(uintptr_t)
					     (parseptr + 6)));
		*offset   += 8;
		*parseptr += 8;
	}

	/* Parse the VLAN header(s), if present */
	if (ethtype == _ODP_ETHTYPE_VLAN_OUTER) {
		prs->input_flags.vlan_qinq = 1;
		prs->input_flags.vlan = 1;

		vlan = (const _odp_vlanhdr_t *)*parseptr;
		ethtype = odp_be_to_cpu_16(vlan->type);
		*offset += sizeof(_odp_vlanhdr_t);
		*parseptr += sizeof(_odp_vlanhdr_t);
	}

	if (ethtype == _ODP_ETHTYPE_VLAN) {
		prs->input_flags.vlan = 1;
		vlan = (const _odp_vlanhdr_t *)*parseptr;
		ethtype = odp_be_to_cpu_16(vlan->type);
		*offset += sizeof(_odp_vlanhdr_t);
		*parseptr += sizeof(_odp_vlanhdr_t);
	}

	return ethtype;
}

/**
 * Parser helper function for IPv4
 */
static inline uint8_t parse_ipv4(packet_parser_t *prs, const uint8_t **parseptr,
				 uint32_t *offset, uint32_t frame_len)
{
	const _odp_ipv4hdr_t *ipv4 = (const _odp_ipv4hdr_t *)*parseptr;
	uint8_t ver = _ODP_IPV4HDR_VER(ipv4->ver_ihl);
	uint8_t ihl = _ODP_IPV4HDR_IHL(ipv4->ver_ihl);
	uint16_t frag_offset;
	uint32_t dstaddr = odp_be_to_cpu_32(ipv4->dst_addr);
	uint32_t l3_len = odp_be_to_cpu_16(ipv4->tot_len);

	if (odp_unlikely(ihl < _ODP_IPV4HDR_IHL_MIN) ||
	    odp_unlikely(ver != 4) ||
	    (l3_len > frame_len - *offset)) {
		prs->error_flags.ip_err = 1;
		return 0;
	}

	*offset   += ihl * 4;
	*parseptr += ihl * 4;

	if (odp_unlikely(ihl > _ODP_IPV4HDR_IHL_MIN))
		prs->input_flags.ipopt = 1;

	/* A packet is a fragment if:
	*  "more fragments" flag is set (all fragments except the last)
	*     OR
	*  "fragment offset" field is nonzero (all fragments except the first)
	*/
	frag_offset = odp_be_to_cpu_16(ipv4->frag_offset);
	if (odp_unlikely(_ODP_IPV4HDR_IS_FRAGMENT(frag_offset)))
		prs->input_flags.ipfrag = 1;

	/* Handle IPv4 broadcast / multicast */
	prs->input_flags.ip_bcast = (dstaddr == 0xffffffff);
	prs->input_flags.ip_mcast = (dstaddr >> 28) == 0xd;

	return ipv4->proto;
}

/**
 * Parser helper function for IPv6
 */
static inline uint8_t parse_ipv6(packet_parser_t *prs, const uint8_t **parseptr,
				 uint32_t *offset, uint32_t frame_len,
				 uint32_t seg_len)
{
	const _odp_ipv6hdr_t *ipv6 = (const _odp_ipv6hdr_t *)*parseptr;
	const _odp_ipv6hdr_ext_t *ipv6ext;
	uint32_t dstaddr0 = odp_be_to_cpu_32(ipv6->dst_addr.u8[0]);
	uint32_t l3_len = odp_be_to_cpu_16(ipv6->payload_len) +
			_ODP_IPV6HDR_LEN;

	/* Basic sanity checks on IPv6 header */
	if ((odp_be_to_cpu_32(ipv6->ver_tc_flow) >> 28) != 6 ||
	    l3_len > frame_len - *offset) {
		prs->error_flags.ip_err = 1;
		return 0;
	}

	/* IPv6 broadcast / multicast flags */
	prs->input_flags.ip_mcast = (dstaddr0 & 0xff000000) == 0xff000000;
	prs->input_flags.ip_bcast = 0;

	/* Skip past IPv6 header */
	*offset   += sizeof(_odp_ipv6hdr_t);
	*parseptr += sizeof(_odp_ipv6hdr_t);

	/* Skip past any IPv6 extension headers */
	if (ipv6->next_hdr == _ODP_IPPROTO_HOPOPTS ||
	    ipv6->next_hdr == _ODP_IPPROTO_ROUTE) {
		prs->input_flags.ipopt = 1;

		do  {
			ipv6ext    = (const _odp_ipv6hdr_ext_t *)*parseptr;
			uint16_t extlen = 8 + ipv6ext->ext_len * 8;

			*offset   += extlen;
			*parseptr += extlen;
		} while ((ipv6ext->next_hdr == _ODP_IPPROTO_HOPOPTS ||
			  ipv6ext->next_hdr == _ODP_IPPROTO_ROUTE) &&
			 *offset < seg_len);

		if (*offset >= prs->l3_offset +
		    odp_be_to_cpu_16(ipv6->payload_len)) {
			prs->error_flags.ip_err = 1;
			return 0;
		}

		if (ipv6ext->next_hdr == _ODP_IPPROTO_FRAG)
			prs->input_flags.ipfrag = 1;

		return ipv6ext->next_hdr;
	}

	if (odp_unlikely(ipv6->next_hdr == _ODP_IPPROTO_FRAG)) {
		prs->input_flags.ipopt = 1;
		prs->input_flags.ipfrag = 1;
	}

	return ipv6->next_hdr;
}

/**
 * Parser helper function for TCP
 */
static inline void parse_tcp(packet_parser_t *prs,
			     const uint8_t **parseptr, uint32_t *offset)
{
	const _odp_tcphdr_t *tcp = (const _odp_tcphdr_t *)*parseptr;

	if (tcp->hl < sizeof(_odp_tcphdr_t) / sizeof(uint32_t))
		prs->error_flags.tcp_err = 1;
	else if ((uint32_t)tcp->hl * 4 > sizeof(_odp_tcphdr_t))
		prs->input_flags.tcpopt = 1;

	if (offset)
		*offset   += (uint32_t)tcp->hl * 4;
	*parseptr += (uint32_t)tcp->hl * 4;
}

/**
 * Parser helper function for UDP
 */
static inline void parse_udp(packet_parser_t *prs,
			     const uint8_t **parseptr, uint32_t *offset)
{
	const _odp_udphdr_t *udp = (const _odp_udphdr_t *)*parseptr;
	uint32_t udplen = odp_be_to_cpu_16(udp->length);

	if (odp_unlikely(udplen < sizeof(_odp_udphdr_t)))
		prs->error_flags.udp_err = 1;

	if (offset)
		*offset   += sizeof(_odp_udphdr_t);
	*parseptr += sizeof(_odp_udphdr_t);
}

static inline
int packet_parse_common_l3_l4(packet_parser_t *prs, const uint8_t *parseptr,
			      uint32_t offset,
			      uint32_t frame_len, uint32_t seg_len,
			      odp_pktio_parser_layer_t layer,
			      uint16_t ethtype)
{
	uint8_t  ip_proto;

	if (layer <= ODP_PKTIO_PARSER_LAYER_L2)
		return prs->error_flags.all != 0;

	/* Set l3_offset+flag only for known ethtypes */
	prs->l3_offset = offset;
	prs->input_flags.l3 = 1;

	/* Parse Layer 3 headers */
	switch (ethtype) {
	case _ODP_ETHTYPE_IPV4:
		prs->input_flags.ipv4 = 1;
		ip_proto = parse_ipv4(prs, &parseptr, &offset, frame_len);
		break;

	case _ODP_ETHTYPE_IPV6:
		prs->input_flags.ipv6 = 1;
		ip_proto = parse_ipv6(prs, &parseptr, &offset, frame_len,
				      seg_len);
		break;

	case _ODP_ETHTYPE_ARP:
		prs->input_flags.arp = 1;
		ip_proto = 255;  /* Reserved invalid by IANA */
		break;

	default:
		prs->input_flags.l3 = 0;
		prs->l3_offset = ODP_PACKET_OFFSET_INVALID;
		ip_proto = 255;  /* Reserved invalid by IANA */
	}

	if (layer == ODP_PKTIO_PARSER_LAYER_L3)
		return prs->error_flags.all != 0;

	/* Set l4_offset+flag only for known ip_proto */
	prs->l4_offset = offset;
	prs->input_flags.l4 = 1;

	/* Parse Layer 4 headers */
	switch (ip_proto) {
	case _ODP_IPPROTO_ICMPv4:
	/* Fall through */

	case _ODP_IPPROTO_ICMPv6:
		prs->input_flags.icmp = 1;
		break;

	case _ODP_IPPROTO_IPIP:
		/* Do nothing */
		break;

	case _ODP_IPPROTO_TCP:
		if (odp_unlikely(offset + _ODP_TCPHDR_LEN > seg_len))
			return -1;
		prs->input_flags.tcp = 1;
		parse_tcp(prs, &parseptr, NULL);
		break;

	case _ODP_IPPROTO_UDP:
		if (odp_unlikely(offset + _ODP_UDPHDR_LEN > seg_len))
			return -1;
		prs->input_flags.udp = 1;
		parse_udp(prs, &parseptr, NULL);
		break;

	case _ODP_IPPROTO_AH:
		prs->input_flags.ipsec = 1;
		prs->input_flags.ipsec_ah = 1;
		break;

	case _ODP_IPPROTO_ESP:
		prs->input_flags.ipsec = 1;
		prs->input_flags.ipsec_esp = 1;
		break;

	case _ODP_IPPROTO_SCTP:
		prs->input_flags.sctp = 1;
		break;

	default:
		prs->input_flags.l4 = 0;
		prs->l4_offset = ODP_PACKET_OFFSET_INVALID;
		break;
	}

	return prs->error_flags.all != 0;
}

/**
 * Parse common packet headers up to given layer
 *
 * The function expects at least PACKET_PARSE_SEG_LEN bytes of data to be
 * available from the ptr.
 */
int packet_parse_common(packet_parser_t *prs, const uint8_t *ptr,
			uint32_t frame_len, uint32_t seg_len,
			odp_pktio_parser_layer_t layer)
{
	uint32_t offset;
	uint16_t ethtype;
	const uint8_t *parseptr;

	parseptr = ptr;
	offset = 0;

	if (layer == ODP_PKTIO_PARSER_LAYER_NONE)
		return 0;

	/* Assume valid L2 header, no CRC/FCS check in SW */
	prs->l2_offset = offset;
	prs->input_flags.l2 = 1;
	/* We only support Ethernet for now */
	prs->input_flags.eth = 1;

	ethtype = parse_eth(prs, &parseptr, &offset, frame_len);

	return packet_parse_common_l3_l4(prs, parseptr, offset, frame_len,
					 seg_len, layer, ethtype);
}

/**
 * Simple packet parser
 */
int packet_parse_layer(odp_packet_hdr_t *pkt_hdr,
		       odp_pktio_parser_layer_t layer)
{
	return packet_parse_common(&pkt_hdr->p,
				   packet_base_data(pkt_hdr),
				   pkt_hdr->frame_len,
				   pkt_hdr->buf_hdr.size,
				   layer);
}

int packet_parse_l3_l4(odp_packet_hdr_t *pkt_hdr,
		       odp_pktio_parser_layer_t layer,
		       uint32_t l3_offset,
		       uint16_t ethtype)
{
	uint32_t seg_len = 0;
	void *base = packet_map(pkt_hdr, l3_offset, &seg_len, NULL);

	if (seg_len == 0)
		return -1;

	return packet_parse_common_l3_l4(&pkt_hdr->p, base, l3_offset,
					 pkt_hdr->frame_len, seg_len,
					 layer, ethtype);
}

uint64_t odp_packet_to_u64(odp_packet_t hdl)
{
	return _odp_pri(hdl);
}

uint64_t odp_packet_seg_to_u64(odp_packet_seg_t hdl)
{
	return _odp_pri(hdl);
}

odp_packet_t odp_packet_ref_static(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	packet_ref_inc(pkt_hdr);

	return pkt;
}

odp_packet_t odp_packet_ref(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	odp_packet_hdr_t *seg;
	odp_packet_hdr_t *ref_hdr;
	odp_packet_t ref;
	uint32_t bytes_skipped, segs_skipped;
	uint32_t len;

	if (offset >= pkt_hdr->frame_len) {
		ODP_DBG("offset too large\n");
		return ODP_PACKET_INVALID;
	}

	seg = get_seg_at_offset(pkt_hdr, offset, &bytes_skipped, &segs_skipped);

	if (packet_alloc(pkt_hdr->buf_hdr.pool_ptr, 0, 1, &ref) != 1) {
		ODP_DBG("segment alloc failed\n");
		return ODP_PACKET_INVALID;
	}
	ref_hdr = packet_hdr(ref);

	len = pkt_hdr->frame_len - offset;

	ref_hdr->buf_hdr.segcount =
		1 + (pkt_hdr->buf_hdr.segcount - segs_skipped);
	ref_hdr->buf_hdr.next_seg = seg;

	ref_hdr->frame_len = len;

	ref_hdr->tailroom = pkt_hdr->tailroom;
	ref_hdr->headroom = 0;

	/* Bump refcnt of trailing segments. */
	do {
		buffer_ref_inc(&seg->buf_hdr);

		seg = seg->buf_hdr.next_seg;
	} while (seg);

	return ref;
}

odp_packet_t odp_packet_ref_pkt(odp_packet_t pkt, uint32_t offset,
				odp_packet_t hdr)
{
	odp_packet_t ref;
	int ret;

	ref = odp_packet_ref(pkt, offset);

	if (ref == ODP_PACKET_INVALID) {
		ODP_DBG("reference create failed\n");
		return ODP_PACKET_INVALID;
	}

	ret = odp_packet_concat(&hdr, ref);

	if (ret < 0) {
		ODP_DBG("concat failed\n");
		odp_packet_free(ref);
		return ODP_PACKET_INVALID;
	}

	return hdr;

}

int odp_packet_has_ref(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = (odp_packet_hdr_t *)(uintptr_t)pkt;

	while (pkt_hdr) {
		uint32_t ref_cnt = buffer_ref(&pkt_hdr->buf_hdr);

		if (is_multi_ref(ref_cnt))
			return 1;

		pkt_hdr = pkt_hdr->buf_hdr.next_seg;
	}

	return 0;
}

/* Include non-inlined versions of API functions */
#if ODP_ABI_COMPAT == 1
#include <odp/api/plat/packet_inlines_api.h>
#endif
