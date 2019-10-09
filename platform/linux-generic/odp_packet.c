/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/autoheader_external.h>

#include <odp/api/packet.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp_packet_internal.h>
#include <odp_debug_internal.h>
#include <odp_errno_define.h>
#include <odp/api/hints.h>
#include <odp/api/byteorder.h>
#include <odp/api/plat/byteorder_inlines.h>
#include <odp/api/packet_io.h>
#include <odp/api/plat/pktio_inlines.h>

/* Inlined API functions */
#include <odp/api/plat/event_inlines.h>

#include <protocols/eth.h>
#include <protocols/ip.h>
#include <protocols/sctp.h>
#include <protocols/tcp.h>
#include <protocols/udp.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include <odp/visibility_begin.h>

/* Fill in packet header field offsets for inline functions */
const _odp_packet_inline_offset_t ODP_ALIGNED_CACHE _odp_packet_inline = {
	.seg_data       = offsetof(odp_packet_hdr_t, seg_data),
	.seg_len        = offsetof(odp_packet_hdr_t, seg_len),
	.seg_next       = offsetof(odp_packet_hdr_t, seg_next),
	.frame_len      = offsetof(odp_packet_hdr_t, frame_len),
	.headroom       = offsetof(odp_packet_hdr_t, headroom),
	.tailroom       = offsetof(odp_packet_hdr_t, tailroom),
	.pool           = offsetof(odp_packet_hdr_t, buf_hdr.pool_ptr),
	.input          = offsetof(odp_packet_hdr_t, input),
	.seg_count      = offsetof(odp_packet_hdr_t, seg_count),
	.user_ptr       = offsetof(odp_packet_hdr_t, buf_hdr.user_ptr),
	.user_area      = offsetof(odp_packet_hdr_t, buf_hdr.uarea_addr),
	.l2_offset      = offsetof(odp_packet_hdr_t, p.l2_offset),
	.l3_offset      = offsetof(odp_packet_hdr_t, p.l3_offset),
	.l4_offset      = offsetof(odp_packet_hdr_t, p.l4_offset),
	.flow_hash      = offsetof(odp_packet_hdr_t, flow_hash),
	.timestamp      = offsetof(odp_packet_hdr_t, timestamp),
	.input_flags    = offsetof(odp_packet_hdr_t, p.input_flags),
	.flags          = offsetof(odp_packet_hdr_t, p.flags),
	.subtype        = offsetof(odp_packet_hdr_t, subtype)

};

#include <odp/visibility_end.h>

/* Check that invalid values are the same. Some versions of Clang have trouble
 * with the strong type casting, and complain that these invalid values are not
 * integral constants. */
#ifndef __clang__
ODP_STATIC_ASSERT(ODP_PACKET_INVALID == 0, "Packet invalid not 0");
ODP_STATIC_ASSERT(ODP_BUFFER_INVALID == 0, "Buffer invalid not 0");
ODP_STATIC_ASSERT(ODP_EVENT_INVALID  == 0, "Event invalid not 0");
#endif

static inline odp_buffer_t packet_to_buffer(odp_packet_t pkt)
{
	return (odp_buffer_t)pkt;
}

static inline odp_packet_hdr_t *packet_seg_to_hdr(odp_packet_seg_t seg)
{
	return (odp_packet_hdr_t *)(uintptr_t)seg;
}

static inline odp_packet_seg_t packet_hdr_to_seg(odp_packet_hdr_t *pkt_hdr)
{
	return (odp_packet_seg_t)pkt_hdr;
}

/*
 * Return pointer to the current segment and step cur_hdr forward.
 */
static inline odp_packet_hdr_t *packet_seg_step(odp_packet_hdr_t **cur_hdr)
{
	odp_packet_hdr_t *hdr = *cur_hdr;

	*cur_hdr = hdr->seg_next;

	return hdr;
}

static inline void packet_seg_find_idx(odp_packet_hdr_t **pkt_hdr,
				       uint32_t find_idx)
{
	odp_packet_hdr_t *hdr = *pkt_hdr;
	uint32_t idx = 0;

	while (odp_unlikely(idx < find_idx)) {
		idx++;
		hdr = hdr->seg_next;
	}

	*pkt_hdr = hdr;
}

static inline uint32_t packet_seg_len(odp_packet_hdr_t *pkt_hdr,
				      uint32_t seg_idx)
{
	packet_seg_find_idx(&pkt_hdr, seg_idx);

	return pkt_hdr->seg_len;
}

static inline uint32_t packet_first_seg_len(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->seg_len;
}

static inline void *packet_data(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->seg_data;
}

static inline void *packet_tail(odp_packet_hdr_t *pkt_hdr)
{
	odp_packet_hdr_t *last_seg = packet_last_seg(pkt_hdr);

	return last_seg->seg_data + last_seg->seg_len;
}

static inline uint32_t seg_headroom(odp_packet_hdr_t *pkt_seg)
{
	odp_buffer_hdr_t *hdr = &pkt_seg->buf_hdr;
	uint8_t *base = hdr->base_data;
	uint8_t *head = pkt_seg->seg_data;

	return CONFIG_PACKET_HEADROOM + (head - base);
}

static inline uint32_t seg_tailroom(odp_packet_hdr_t *pkt_seg)
{
	odp_buffer_hdr_t *hdr = &pkt_seg->buf_hdr;
	uint8_t *tail         = pkt_seg->seg_data + pkt_seg->seg_len;

	return hdr->buf_end - tail;
}

static inline void push_head(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	pkt_hdr->headroom  -= len;
	pkt_hdr->frame_len += len;
	pkt_hdr->seg_data -= len;
	pkt_hdr->seg_len  += len;
}

static inline void pull_head(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	pkt_hdr->headroom  += len;
	pkt_hdr->frame_len -= len;
	pkt_hdr->seg_data += len;
	pkt_hdr->seg_len  -= len;
}

static inline void push_tail(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	odp_packet_hdr_t *last_seg = packet_last_seg(pkt_hdr);

	pkt_hdr->tailroom  -= len;
	pkt_hdr->frame_len += len;
	last_seg->seg_len  += len;
}

/* Copy all metadata for segmentation modification. Segment data and lengths
 * are not copied. */
static inline void packet_seg_copy_md(odp_packet_hdr_t *dst,
				      odp_packet_hdr_t *src)
{
	dst->p = src->p;

	/* lengths are not copied:
	 *   .frame_len
	 *   .headroom
	 *   .tailroom
	 */

	dst->input     = src->input;
	dst->dst_queue = src->dst_queue;
	dst->flow_hash = src->flow_hash;
	dst->timestamp = src->timestamp;

	/* buffer header side packet metadata */
	dst->buf_hdr.user_ptr   = src->buf_hdr.user_ptr;
	dst->buf_hdr.uarea_addr = src->buf_hdr.uarea_addr;

	/* segmentation data is not copied:
	 *   seg_next
	 *   seg_data
	 *   seg_len
	 *   seg_count
	 */
}

static inline void *packet_map(void *pkt_ptr, uint32_t offset,
			       uint32_t *seg_len, odp_packet_seg_t *seg)
{
	void *addr;
	uint32_t len;
	odp_packet_hdr_t *pkt_hdr = pkt_ptr;
	int seg_count = pkt_hdr->seg_count;

	if (odp_unlikely(offset >= pkt_hdr->frame_len))
		return NULL;

	if (odp_likely(seg_count == 1)) {
		addr = pkt_hdr->seg_data + offset;
		len  = pkt_hdr->seg_len - offset;
	} else {
		odp_packet_hdr_t *next_hdr = pkt_hdr;
		uint32_t seg_start = 0, seg_end = 0;

		while (next_hdr != NULL) {
			pkt_hdr = packet_seg_step(&next_hdr);
			seg_end += pkt_hdr->seg_len;

			if (odp_likely(offset < seg_end))
				break;

			seg_start = seg_end;
		}

		addr = pkt_hdr->seg_data + (offset - seg_start);
		len  = pkt_hdr->seg_len  - (offset - seg_start);
	}

	if (seg_len)
		*seg_len = len;

	if (seg)
		*seg = packet_hdr_to_seg(pkt_hdr);

	return addr;
}

#include <odp/visibility_begin.h>

/* This file uses the inlined version directly. Inlined API calls use this when
 * offset does not point to the first segment. */
void *_odp_packet_map(void *pkt_ptr, uint32_t offset, uint32_t *seg_len,
		      odp_packet_seg_t *seg)
{
	return packet_map(pkt_ptr, offset, seg_len, seg);
}

int _odp_packet_copy_from_mem_seg(odp_packet_t pkt, uint32_t offset,
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

int _odp_packet_copy_to_mem_seg(odp_packet_t pkt, uint32_t offset,
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

#include <odp/visibility_end.h>

void packet_parse_reset(odp_packet_hdr_t *pkt_hdr)
{
	/* Reset parser metadata before new parse */
	pkt_hdr->p.input_flags.all  = 0;
	pkt_hdr->p.flags.all.error  = 0;
	pkt_hdr->p.l2_offset        = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->p.l3_offset        = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->p.l4_offset        = ODP_PACKET_OFFSET_INVALID;
}

static inline void link_segments(odp_packet_hdr_t *pkt_hdr[], int num)
{
	int cur = 0;
	odp_packet_hdr_t *hdr;
	odp_packet_hdr_t *head = pkt_hdr[0];
	uint32_t seg_len = ((pool_t *)(head->buf_hdr.pool_ptr))->seg_len;

	while (1) {
		odp_buffer_hdr_t *buf_hdr = &pkt_hdr[cur]->buf_hdr;

		hdr = pkt_hdr[cur];
		hdr->seg_data = buf_hdr->base_data;
		hdr->seg_len  = seg_len;

		/* init_segments() handles first seg ref_cnt init */
		if (ODP_DEBUG == 1 && cur > 0) {
			uint32_t prev_ref;
			odp_atomic_u32_t *ref_cnt;

			ref_cnt = &pkt_hdr[cur]->buf_hdr.ref_cnt;
			prev_ref = odp_atomic_fetch_inc_u32(ref_cnt);

			ODP_ASSERT(prev_ref == 0);
		}

		cur++;

		if (cur == num) {
			/* Last segment */
			hdr->seg_next  = NULL;
			return;
		}

		hdr->seg_next = pkt_hdr[cur];
	}
}

static inline void init_segments(odp_packet_hdr_t *pkt_hdr[], int num)
{
	odp_packet_hdr_t *hdr;
	uint32_t seg_len;

	/* First segment is the packet descriptor */
	hdr = pkt_hdr[0];
	seg_len = ((pool_t *)(hdr->buf_hdr.pool_ptr))->seg_len;

	/* Defaults for single segment packet */
	hdr->seg_data = hdr->buf_hdr.base_data;
	hdr->seg_len  = seg_len;
	hdr->seg_next = NULL;

	hdr->seg_count = num;

	if (ODP_DEBUG == 1) {
		uint32_t prev_ref =
			odp_atomic_fetch_inc_u32(&hdr->buf_hdr.ref_cnt);

		ODP_ASSERT(prev_ref == 0);
	}

	/* Link segments */
	if (odp_unlikely(num > 1))
		link_segments(pkt_hdr, num);
}

static inline void reset_segments(odp_packet_hdr_t *pkt_hdr)
{
	void *base;
	uint32_t seg_len = ((pool_t *)(pkt_hdr->buf_hdr.pool_ptr))->seg_len;

	while (pkt_hdr != NULL) {
		base = pkt_hdr->buf_hdr.base_data;

		pkt_hdr->seg_len  = seg_len;
		pkt_hdr->seg_data = base;

		pkt_hdr = pkt_hdr->seg_next;
	}
}

/* Calculate the number of segments */
static inline int num_segments(uint32_t len, uint32_t seg_len)
{
	int num = 1;

	if (odp_unlikely(len > seg_len)) {
		num = len / seg_len;

		if (odp_likely((num * seg_len) != len))
			num += 1;
	}

	return num;
}

static inline void add_all_segs(odp_packet_hdr_t *to, odp_packet_hdr_t *from)
{
	odp_packet_hdr_t *last = packet_last_seg(to);

	last->seg_next = from;
	to->seg_count  += from->seg_count;
}

static inline odp_packet_hdr_t *alloc_segments(pool_t *pool, int num)
{
	odp_packet_hdr_t *pkt_hdr[num];
	int ret;

	ret = buffer_alloc_multi(pool, (odp_buffer_hdr_t **)pkt_hdr, num);

	if (odp_unlikely(ret != num)) {
		if (ret > 0)
			buffer_free_multi((odp_buffer_hdr_t **)pkt_hdr, ret);

		return NULL;
	}

	init_segments(pkt_hdr, num);

	return pkt_hdr[0];
}

static inline odp_packet_hdr_t *add_segments(odp_packet_hdr_t *pkt_hdr,
					     pool_t *pool, uint32_t len,
					     int num, int head)
{
	odp_packet_hdr_t *new_hdr;
	uint32_t seg_len, offset;

	new_hdr = alloc_segments(pool, num);

	if (new_hdr == NULL)
		return NULL;

	seg_len = len - ((num - 1) * pool->seg_len);
	offset  = pool->seg_len - seg_len;

	if (head) {
		/* add into the head*/
		add_all_segs(new_hdr, pkt_hdr);

		/* adjust first segment length */
		new_hdr->seg_data += offset;
		new_hdr->seg_len   = seg_len;

		packet_seg_copy_md(new_hdr, pkt_hdr);
		new_hdr->frame_len = pkt_hdr->frame_len + len;
		new_hdr->headroom  = pool->headroom + offset;
		new_hdr->tailroom  = pkt_hdr->tailroom;

		pkt_hdr = new_hdr;
	} else {
		odp_packet_hdr_t *last_seg;

		/* add into the tail */
		add_all_segs(pkt_hdr, new_hdr);

		/* adjust last segment length */
		last_seg = packet_last_seg(pkt_hdr);
		last_seg->seg_len = seg_len;

		pkt_hdr->frame_len += len;
		pkt_hdr->tailroom   = pool->tailroom + offset;
	}

	return pkt_hdr;
}

static inline void buffer_ref_inc(odp_buffer_hdr_t *buf_hdr)
{
	uint32_t ref_cnt = odp_atomic_load_u32(&buf_hdr->ref_cnt);

	/* First count increment after alloc */
	if (odp_likely(ref_cnt) == 0)
		odp_atomic_store_u32(&buf_hdr->ref_cnt, 2);
	else
		odp_atomic_inc_u32(&buf_hdr->ref_cnt);
}

static inline uint32_t buffer_ref_dec(odp_buffer_hdr_t *buf_hdr)
{
	return odp_atomic_fetch_dec_u32(&buf_hdr->ref_cnt);
}

static inline uint32_t buffer_ref(odp_buffer_hdr_t *buf_hdr)
{
	return odp_atomic_load_u32(&buf_hdr->ref_cnt);
}

static inline int is_multi_ref(uint32_t ref_cnt)
{
	return (ref_cnt > 1);
}

static inline void packet_ref_inc(odp_packet_hdr_t *pkt_hdr)
{
	odp_packet_hdr_t *hdr = pkt_hdr;

	while (hdr != NULL) {
		buffer_ref_inc(&hdr->buf_hdr);
		hdr = hdr->seg_next;
	}
}

static inline void packet_free_multi(odp_buffer_hdr_t *hdr[], int num)
{
	int i;
	uint32_t ref_cnt;
	int num_ref = 0;

	for (i = 0; i < num; i++) {
		/* Zero when reference API has not been used */
		ref_cnt = buffer_ref(hdr[i]);

		if (odp_unlikely(ref_cnt)) {
			ref_cnt = buffer_ref_dec(hdr[i]);

			if (is_multi_ref(ref_cnt)) {
				num_ref++;
				continue;
			}
		}

		/* Skip references and pack to be freed headers to array head */
		if (odp_unlikely(num_ref))
			hdr[i - num_ref] = hdr[i];

	}

	num -= num_ref;

	if (odp_likely(num))
		buffer_free_multi(hdr, num);
}

static inline void free_all_segments(odp_packet_hdr_t *pkt_hdr, int num)
{
	int i;
	odp_buffer_hdr_t *buf_hdr[num];
	odp_packet_hdr_t *seg_hdr = pkt_hdr;

	for (i = 0; i < num; i++) {
		buf_hdr[i] = &seg_hdr->buf_hdr;
		seg_hdr = seg_hdr->seg_next;
	}

	packet_free_multi(buf_hdr, num);
}

static inline odp_packet_hdr_t *free_segments(odp_packet_hdr_t *pkt_hdr,
					      int num, uint32_t free_len,
					      uint32_t pull_len, int head)
{
	odp_packet_hdr_t *seg_hdr;
	int i;
	int num_remain = pkt_hdr->seg_count - num;
	odp_packet_hdr_t *hdr = pkt_hdr;
	odp_packet_hdr_t *last_hdr = packet_last_seg(pkt_hdr);
	odp_buffer_hdr_t *buf_hdr[num];

	if (head) {
		odp_packet_hdr_t *new_hdr;

		for (i = 0; i < num; i++) {
			seg_hdr    = packet_seg_step(&hdr);
			buf_hdr[i] = &seg_hdr->buf_hdr;
		}

		/* The first remaining header is the new packet descriptor.
		 * Copy remaining segments from the last to-be-removed header
		 * to the new header. */
		new_hdr = hdr;

		new_hdr->seg_next = hdr->seg_next;
		new_hdr->seg_count = num_remain;

		packet_seg_copy_md(new_hdr, pkt_hdr);

		/* Tailroom not changed */
		new_hdr->tailroom  = pkt_hdr->tailroom;

		new_hdr->headroom = seg_headroom(new_hdr);

		new_hdr->frame_len  = pkt_hdr->frame_len - free_len;

		pull_head(new_hdr, pull_len);

		pkt_hdr = new_hdr;

		packet_free_multi(buf_hdr, num);
	} else {
		/* Free last 'num' bufs.
		 * First, find the last remaining header. */
		packet_seg_find_idx(&hdr, num_remain - 1);
		last_hdr = hdr;

		packet_seg_step(&hdr);

		for (i = 0; i < num; i++) {
			seg_hdr    = packet_seg_step(&hdr);
			buf_hdr[i] = &seg_hdr->buf_hdr;
		}

		packet_free_multi(buf_hdr, num);

		/* Head segment remains, no need to copy or update majority
		 * of the metadata. */
		last_hdr->seg_next = NULL;

		pkt_hdr->seg_count = num_remain;
		pkt_hdr->frame_len -= free_len;
		pkt_hdr->tailroom = seg_tailroom(pkt_hdr);

		pull_tail(pkt_hdr, pull_len);
	}

	return pkt_hdr;
}

static inline int packet_alloc(pool_t *pool, uint32_t len, int max_pkt,
			       int num_seg, odp_packet_t *pkt)
{
	int num_buf, i;
	int num     = max_pkt;
	int max_buf = max_pkt * num_seg;
	odp_packet_hdr_t *pkt_hdr[max_buf];
	odp_packet_hdr_t *hdr_next;
	odp_packet_hdr_t *hdr;

	num_buf = buffer_alloc_multi(pool, (odp_buffer_hdr_t **)pkt_hdr,
				     max_buf);

	/* Failed to allocate all segments */
	if (odp_unlikely(num_buf != max_buf)) {
		int num_free;

		num      = num_buf / num_seg;
		num_free = num_buf - (num * num_seg);

		if (num_free > 0) {
			odp_buffer_hdr_t **p;

			p = (odp_buffer_hdr_t **)&pkt_hdr[num_buf - num_free];
			buffer_free_multi(p, num_free);
		}

		if (num == 0)
			return 0;
	}

	hdr_next = pkt_hdr[0];
	odp_prefetch(hdr_next);
	odp_prefetch((uint8_t *)hdr_next + ODP_CACHE_LINE_SIZE);

	for (i = 0; i < num - 1; i++) {
		hdr = hdr_next;
		hdr_next = pkt_hdr[(i + 1) * num_seg];

		odp_prefetch(hdr_next);
		odp_prefetch((uint8_t *)hdr_next + ODP_CACHE_LINE_SIZE);

		/* First buffer is the packet descriptor */
		pkt[i] = packet_handle(hdr);
		init_segments(&pkt_hdr[i * num_seg], num_seg);

		packet_init(hdr, len);
	}

	/* Last packet */
	pkt[i] = packet_handle(hdr_next);
	init_segments(&pkt_hdr[i * num_seg], num_seg);
	packet_init(hdr_next, len);

	return num;
}

int packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
		       odp_packet_t pkt[], int max_num)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);
	int num, num_seg;

	num_seg = num_segments(len, pool->seg_len);
	num     = packet_alloc(pool, len, max_num, num_seg, pkt);

	return num;
}

odp_packet_t odp_packet_alloc(odp_pool_t pool_hdl, uint32_t len)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);
	odp_packet_t pkt;
	int num, num_seg;

	if (odp_unlikely(pool->params.type != ODP_POOL_PACKET)) {
		__odp_errno = EINVAL;
		return ODP_PACKET_INVALID;
	}

	if (odp_unlikely(len > pool->max_len))
		return ODP_PACKET_INVALID;

	num_seg = num_segments(len, pool->seg_len);
	num     = packet_alloc(pool, len, 1, num_seg, &pkt);

	if (odp_unlikely(num == 0))
		return ODP_PACKET_INVALID;

	return pkt;
}

int odp_packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
			   odp_packet_t pkt[], int max_num)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);
	int num, num_seg;

	if (odp_unlikely(pool->params.type != ODP_POOL_PACKET)) {
		__odp_errno = EINVAL;
		return -1;
	}

	if (odp_unlikely(len > pool->max_len))
		return -1;

	num_seg = num_segments(len, pool->seg_len);
	num     = packet_alloc(pool, len, max_num, num_seg, pkt);

	return num;
}

void odp_packet_free(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	int num_seg = pkt_hdr->seg_count;

	ODP_ASSERT(buffer_ref(&pkt_hdr->buf_hdr) > 0);

	if (odp_likely(num_seg == 1)) {
		odp_buffer_hdr_t *buf_hdr = &pkt_hdr->buf_hdr;

		packet_free_multi(&buf_hdr, 1);
	} else {
		free_all_segments(pkt_hdr, num_seg);
	}
}

void odp_packet_free_multi(const odp_packet_t pkt[], int num)
{
	odp_buffer_hdr_t *buf_hdr[num];
	int i;
	int num_freed = 0;

	for (i = 0; i < num; i++) {
		odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt[i]);
		int num_seg = pkt_hdr->seg_count;

		ODP_ASSERT(buffer_ref(&pkt_hdr->buf_hdr) > 0);

		if (odp_unlikely(num_seg > 1)) {
			free_all_segments(pkt_hdr, num_seg);
			num_freed++;
			continue;
		}

		buf_hdr[i - num_freed] = &pkt_hdr->buf_hdr;
	}

	if (odp_likely(num - num_freed))
		packet_free_multi(buf_hdr, num - num_freed);
}

void odp_packet_free_sp(const odp_packet_t pkt[], int num)
{
	odp_packet_free_multi(pkt, num);
}

int odp_packet_reset(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *const pkt_hdr = packet_hdr(pkt);
	pool_t *pool = pkt_hdr->buf_hdr.pool_ptr;
	int num = pkt_hdr->seg_count;
	int num_req;

	if (odp_unlikely(len > (pool->seg_len * num)))
		return -1;

	/* Free possible extra segments */
	num_req = num_segments(len, pool->seg_len);
	if (odp_unlikely(num_req < num))
		free_segments(pkt_hdr, num - num_req, 0, 0, 0);
	reset_segments(pkt_hdr);

	packet_init(pkt_hdr, len);

	return 0;
}

int odp_event_filter_packet(const odp_event_t event[],
			    odp_packet_t packet[],
			    odp_event_t remain[], int num)
{
	int i;
	int num_pkt = 0;
	int num_rem = 0;

	for (i = 0; i < num; i++) {
		if (odp_event_type(event[i]) == ODP_EVENT_PACKET) {
			packet[num_pkt] = odp_packet_from_event(event[i]);
			num_pkt++;
		} else {
			remain[num_rem] = event[i];
			num_rem++;
		}
	}

	return num_pkt;
}

/*
 *
 * Pointers and lengths
 * ********************************************************
 *
 */

uint32_t odp_packet_buf_len(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	pool_t *pool = pkt_hdr->buf_hdr.pool_ptr;

	return pool->max_seg_len * pkt_hdr->seg_count;
}

void *odp_packet_tail(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	return packet_tail(pkt_hdr);
}

void *odp_packet_push_head(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (len > pkt_hdr->headroom)
		return NULL;

	push_head(pkt_hdr, len);
	return packet_data(pkt_hdr);
}

int odp_packet_extend_head(odp_packet_t *pkt, uint32_t len,
			   void **data_ptr, uint32_t *seg_len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(*pkt);
	uint32_t frame_len = pkt_hdr->frame_len;
	uint32_t headroom  = pkt_hdr->headroom;
	int ret = 0;

	if (len > headroom) {
		pool_t *pool = pkt_hdr->buf_hdr.pool_ptr;
		int num;
		void *ptr;

		if (odp_unlikely((frame_len + len) > pool->max_len))
			return -1;

		num = num_segments(len - headroom, pool->seg_len);
		if (odp_unlikely(pkt_hdr->seg_count + num > PKT_MAX_SEGS))
			return -1;

		push_head(pkt_hdr, headroom);
		ptr = add_segments(pkt_hdr, pool, len - headroom, num, 1);

		if (ptr == NULL) {
			/* segment alloc failed, rollback changes */
			pull_head(pkt_hdr, headroom);
			return -1;
		}

		*pkt    = packet_handle(ptr);
		pkt_hdr = ptr;
	} else {
		push_head(pkt_hdr, len);
	}

	if (data_ptr)
		*data_ptr = packet_data(pkt_hdr);

	if (seg_len)
		*seg_len = packet_first_seg_len(pkt_hdr);

	return ret;
}

void *odp_packet_pull_head(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (len > pkt_hdr->frame_len)
		return NULL;

	pull_head(pkt_hdr, len);
	return packet_data(pkt_hdr);
}

int odp_packet_trunc_head(odp_packet_t *pkt, uint32_t len,
			  void **data_ptr, uint32_t *seg_len_out)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(*pkt);
	uint32_t seg_len = packet_first_seg_len(pkt_hdr);

	if (len > pkt_hdr->frame_len)
		return -1;

	if (len < seg_len) {
		pull_head(pkt_hdr, len);
	} else {
		int num = 0;
		uint32_t pull_len = 0;

		while (seg_len <= len) {
			pull_len = len - seg_len;
			num++;
			seg_len += packet_seg_len(pkt_hdr, num);
		}

		pkt_hdr = free_segments(pkt_hdr, num, len - pull_len,
					pull_len, 1);
		*pkt    = packet_handle(pkt_hdr);
	}

	if (data_ptr)
		*data_ptr = packet_data(pkt_hdr);

	if (seg_len_out)
		*seg_len_out = packet_first_seg_len(pkt_hdr);

	return 0;
}

void *odp_packet_push_tail(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	void *old_tail;

	if (len > pkt_hdr->tailroom)
		return NULL;

	ODP_ASSERT(odp_packet_has_ref(pkt) == 0);

	old_tail = packet_tail(pkt_hdr);
	push_tail(pkt_hdr, len);

	return old_tail;
}

int odp_packet_extend_tail(odp_packet_t *pkt, uint32_t len,
			   void **data_ptr, uint32_t *seg_len_out)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(*pkt);
	uint32_t frame_len = pkt_hdr->frame_len;
	uint32_t tailroom  = pkt_hdr->tailroom;
	uint32_t tail_off  = frame_len;
	int ret = 0;

	ODP_ASSERT(odp_packet_has_ref(*pkt) == 0);

	if (len > tailroom) {
		pool_t *pool = pkt_hdr->buf_hdr.pool_ptr;
		int num;
		void *ptr;

		if (odp_unlikely((frame_len + len) > pool->max_len))
			return -1;

		num = num_segments(len - tailroom, pool->seg_len);
		if (odp_unlikely(pkt_hdr->seg_count + num > PKT_MAX_SEGS))
			return -1;

		push_tail(pkt_hdr, tailroom);
		ptr = add_segments(pkt_hdr, pool, len - tailroom, num, 0);

		if (ptr == NULL) {
			/* segment alloc failed, rollback changes */
			pull_tail(pkt_hdr, tailroom);
			return -1;
		}
	} else {
		push_tail(pkt_hdr, len);
	}

	if (data_ptr)
		*data_ptr = packet_map(pkt_hdr, tail_off, seg_len_out, NULL);

	return ret;
}

void *odp_packet_pull_tail(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	odp_packet_hdr_t *last_seg = packet_last_seg(pkt_hdr);

	ODP_ASSERT(odp_packet_has_ref(pkt) == 0);

	if (len > last_seg->seg_len)
		return NULL;

	pull_tail(pkt_hdr, len);

	return packet_tail(pkt_hdr);
}

int odp_packet_trunc_tail(odp_packet_t *pkt, uint32_t len,
			  void **tail_ptr, uint32_t *tailroom)
{
	int last;
	uint32_t seg_len;
	odp_packet_hdr_t *last_seg;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(*pkt);

	if (len > pkt_hdr->frame_len)
		return -1;

	ODP_ASSERT(odp_packet_has_ref(*pkt) == 0);

	last     = pkt_hdr->seg_count - 1;
	last_seg = packet_last_seg(pkt_hdr);
	seg_len  = last_seg->seg_len;

	if (len < seg_len) {
		pull_tail(pkt_hdr, len);
	} else {
		int num = 0;
		uint32_t pull_len = 0;

		/* Reverse order */
		while (seg_len <= len) {
			pull_len = len - seg_len;
			num++;
			seg_len += packet_seg_len(pkt_hdr, last - num);
		}

		free_segments(pkt_hdr, num, len - pull_len, pull_len, 0);
	}

	if (tail_ptr)
		*tail_ptr = packet_tail(pkt_hdr);

	if (tailroom)
		*tailroom = pkt_hdr->tailroom;
	return 0;
}

void *odp_packet_offset(odp_packet_t pkt, uint32_t offset, uint32_t *len,
			odp_packet_seg_t *seg)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	void *addr = packet_map(pkt_hdr, offset, len, seg);

	return addr;
}

/*
 *
 * Meta-data
 * ********************************************************
 *
 */

void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ptr)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (odp_unlikely(ptr == NULL)) {
		pkt_hdr->p.flags.user_ptr_set = 0;
		return;
	}

	pkt_hdr->buf_hdr.user_ptr     = ptr;
	pkt_hdr->p.flags.user_ptr_set = 1;
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

int odp_packet_l3_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (offset >= pkt_hdr->frame_len)
		return -1;

	pkt_hdr->p.l3_offset = offset;
	return 0;
}

int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (offset >= pkt_hdr->frame_len)
		return -1;

	pkt_hdr->p.l4_offset = offset;
	return 0;
}

uint16_t odp_packet_ones_comp(odp_packet_t pkt, odp_packet_data_range_t *range)
{
	(void)pkt;
	range->length = 0;
	range->offset = 0;
	return 0;
}

void odp_packet_l3_chksum_insert(odp_packet_t pkt, int insert)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.flags.l3_chksum_set = 1;
	pkt_hdr->p.flags.l3_chksum = insert;
}

void odp_packet_l4_chksum_insert(odp_packet_t pkt, int insert)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.flags.l4_chksum_set = 1;
	pkt_hdr->p.flags.l4_chksum = insert;
}

odp_packet_chksum_status_t odp_packet_l3_chksum_status(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (!pkt_hdr->p.input_flags.l3_chksum_done)
		return ODP_PACKET_CHKSUM_UNKNOWN;

	if (pkt_hdr->p.flags.l3_chksum_err)
		return ODP_PACKET_CHKSUM_BAD;

	return ODP_PACKET_CHKSUM_OK;
}

odp_packet_chksum_status_t odp_packet_l4_chksum_status(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (!pkt_hdr->p.input_flags.l4_chksum_done)
		return ODP_PACKET_CHKSUM_UNKNOWN;

	if (pkt_hdr->p.flags.l4_chksum_err)
		return ODP_PACKET_CHKSUM_BAD;

	return ODP_PACKET_CHKSUM_OK;
}

void odp_packet_flow_hash_set(odp_packet_t pkt, uint32_t flow_hash)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	packet_set_flow_hash(pkt_hdr, flow_hash);
}

void odp_packet_ts_set(odp_packet_t pkt, odp_time_t timestamp)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	packet_set_ts(pkt_hdr, &timestamp);
}

/*
 *
 * Segment level
 * ********************************************************
 *
 */

odp_packet_seg_t odp_packet_last_seg(odp_packet_t pkt)
{
	return (odp_packet_seg_t)packet_last_seg(packet_hdr(pkt));
}

/*
 *
 * Manipulation
 * ********************************************************
 *
 */

int odp_packet_add_data(odp_packet_t *pkt_ptr, uint32_t offset, uint32_t len)
{
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	uint32_t pktlen = pkt_hdr->frame_len;
	pool_t *pool = pkt_hdr->buf_hdr.pool_ptr;
	odp_packet_t newpkt;

	if (offset > pktlen)
		return -1;

	newpkt = odp_packet_alloc(pool->pool_hdl, pktlen + len);

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
	pool_t *pool = pkt_hdr->buf_hdr.pool_ptr;
	odp_packet_t newpkt;

	if (offset > pktlen || offset + len > pktlen)
		return -1;

	newpkt = odp_packet_alloc(pool->pool_hdl, pktlen - len);

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
	pool_t *pool = pkt_hdr->buf_hdr.pool_ptr;
	void *addr = packet_map(pkt_hdr, offset, &seglen, NULL);
	uint64_t uaddr = (uint64_t)(uintptr_t)addr;
	uint64_t misalign;

	if (align > ODP_CACHE_LINE_SIZE)
		return -1;

	ODP_ASSERT(odp_packet_has_ref(*pkt) == 0);

	if (seglen >= len) {
		misalign = align <= 1 ? 0 :
			ROUNDUP_ALIGN(uaddr, align) - uaddr;
		if (misalign == 0)
			return 0;
		shift = align - misalign;
	} else {
		if (len > pool->max_seg_len)
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
				   odp_packet_len(*pkt) - shift);

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

	ODP_ASSERT(odp_packet_has_ref(*dst) == 0);

	if (odp_unlikely(dst_len + src_len > dst_pool->max_len)) {
		ODP_ERR("concat would result oversized packet\n");
		return -1;
	}

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

	if (odp_unlikely(dst_hdr->seg_count + src_hdr->seg_count >
			 PKT_MAX_SEGS))
		return -1;

	add_all_segs(dst_hdr, src_hdr);

	dst_hdr->frame_len = dst_len + src_len;
	dst_hdr->tailroom  = src_hdr->tailroom;

	/* Data was not moved in memory */
	return 0;
}

int odp_packet_split(odp_packet_t *pkt, uint32_t len, odp_packet_t *tail)
{
	uint32_t pktlen = odp_packet_len(*pkt);

	if (len >= pktlen || tail == NULL)
		return -1;

	ODP_ASSERT(odp_packet_has_ref(*pkt) == 0);

	*tail = odp_packet_copy_part(*pkt, len, pktlen - len,
				     odp_packet_pool(*pkt));

	if (*tail == ODP_PACKET_INVALID)
		return -1;

	return odp_packet_trunc_tail(pkt, pktlen - len, NULL, NULL);
}

/*
 *
 * Copy
 * ********************************************************
 *
 */

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
	uint32_t pktlen = odp_packet_len(pkt);
	odp_packet_t newpkt;

	if (offset >= pktlen || offset + len > pktlen)
		return ODP_PACKET_INVALID;

	newpkt = odp_packet_alloc(pool, len);
	if (newpkt != ODP_PACKET_INVALID)
		odp_packet_copy_from_pkt(newpkt, 0, pkt, offset, len);

	return newpkt;
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

/*
 *
 * Debugging
 * ********************************************************
 *
 */
static int packet_print_input_flags(odp_packet_hdr_t *hdr, char *str, int max)
{
	int len = 0;

	if (hdr->p.input_flags.l2)
		len += snprintf(&str[len], max - len, "l2 ");
	if (hdr->p.input_flags.l3)
		len += snprintf(&str[len], max - len, "l3 ");
	if (hdr->p.input_flags.l4)
		len += snprintf(&str[len], max - len, "l4 ");
	if (hdr->p.input_flags.eth)
		len += snprintf(&str[len], max - len, "eth ");
	if (hdr->p.input_flags.vlan)
		len += snprintf(&str[len], max - len, "vlan ");
	if (hdr->p.input_flags.arp)
		len += snprintf(&str[len], max - len, "arp ");
	if (hdr->p.input_flags.ipv4)
		len += snprintf(&str[len], max - len, "ipv4 ");
	if (hdr->p.input_flags.ipv6)
		len += snprintf(&str[len], max - len, "ipv6 ");
	if (hdr->p.input_flags.ipsec)
		len += snprintf(&str[len], max - len, "ipsec ");
	if (hdr->p.input_flags.udp)
		len += snprintf(&str[len], max - len, "udp ");
	if (hdr->p.input_flags.tcp)
		len += snprintf(&str[len], max - len, "tcp ");
	if (hdr->p.input_flags.sctp)
		len += snprintf(&str[len], max - len, "sctp ");
	if (hdr->p.input_flags.icmp)
		len += snprintf(&str[len], max - len, "icmp ");

	return len;
}

void odp_packet_print(odp_packet_t pkt)
{
	odp_packet_seg_t seg;
	int max_len = 4096;
	char str[max_len];
	int len = 0;
	int n = max_len - 1;
	odp_packet_hdr_t *hdr = packet_hdr(pkt);
	odp_buffer_t buf      = packet_to_buffer(pkt);

	len += snprintf(&str[len], n - len, "Packet ");
	len += odp_buffer_snprint(&str[len], n - len, buf);
	len += snprintf(&str[len], n - len, "  input_flags  0x%" PRIx64 "\n",
			hdr->p.input_flags.all);
	if (hdr->p.input_flags.all) {
		len += snprintf(&str[len], n - len, "               ");
		len += packet_print_input_flags(hdr, &str[len], n - len);
		len += snprintf(&str[len], n - len, "\n");
	}
	len += snprintf(&str[len], n - len, "  flags        0x%" PRIx32 "\n",
			hdr->p.flags.all_flags);
	len += snprintf(&str[len], n - len,
			"  l2_offset    %" PRIu32 "\n", hdr->p.l2_offset);
	len += snprintf(&str[len], n - len,
			"  l3_offset    %" PRIu32 "\n", hdr->p.l3_offset);
	len += snprintf(&str[len], n - len,
			"  l4_offset    %" PRIu32 "\n", hdr->p.l4_offset);
	len += snprintf(&str[len], n - len,
			"  frame_len    %" PRIu32 "\n", hdr->frame_len);
	len += snprintf(&str[len], n - len,
			"  input        %" PRIu64 "\n",
			odp_pktio_to_u64(hdr->input));
	len += snprintf(&str[len], n - len,
			"  headroom     %" PRIu32 "\n",
			odp_packet_headroom(pkt));
	len += snprintf(&str[len], n - len,
			"  tailroom     %" PRIu32 "\n",
			odp_packet_tailroom(pkt));
	len += snprintf(&str[len], n - len,
			"  num_segs     %i\n", odp_packet_num_segs(pkt));

	seg = odp_packet_first_seg(pkt);

	while (seg != ODP_PACKET_SEG_INVALID) {
		odp_packet_hdr_t *seg_hdr = packet_seg_to_hdr(seg);
		odp_buffer_hdr_t *buf_hdr = &seg_hdr->buf_hdr;
		char seg_str[max_len];
		int str_len;

		str_len = snprintf(&seg_str[0], max_len,
				   "    seg_len    %-4" PRIu32 "  seg_data %p "
				   "ref_cnt %u\n",
				   odp_packet_seg_data_len(pkt, seg),
				   odp_packet_seg_data(pkt, seg),
				   buffer_ref(buf_hdr));

		/* Prevent print buffer overflow */
		if (n - len - str_len < 10) {
			len += snprintf(&str[len], n - len, "    ...\n");
			break;
		}
		len += snprintf(&str[len], n - len, "%s", seg_str);

		seg = odp_packet_next_seg(pkt, seg);
	}

	ODP_PRINT("%s\n", str);
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
			hdr->buf_hdr.index.buffer);
	len += snprintf(&str[len], n - len,
			"  seg_count      %" PRIu16 "\n", hdr->seg_count);
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

/*
 *
 * Internal Use Routines
 * ********************************************************
 *
 */

int _odp_packet_copy_md_to_packet(odp_packet_t srcpkt, odp_packet_t dstpkt)
{
	odp_packet_hdr_t *srchdr = packet_hdr(srcpkt);
	odp_packet_hdr_t *dsthdr = packet_hdr(dstpkt);
	pool_t *src_pool = srchdr->buf_hdr.pool_ptr;
	pool_t *dst_pool = dsthdr->buf_hdr.pool_ptr;
	uint32_t src_uarea_size = src_pool->params.pkt.uarea_size;
	uint32_t dst_uarea_size = dst_pool->params.pkt.uarea_size;

	dsthdr->input = srchdr->input;
	dsthdr->dst_queue = srchdr->dst_queue;
	dsthdr->buf_hdr.user_ptr = srchdr->buf_hdr.user_ptr;
	if (dsthdr->buf_hdr.uarea_addr != NULL &&
	    srchdr->buf_hdr.uarea_addr != NULL) {
		memcpy(dsthdr->buf_hdr.uarea_addr, srchdr->buf_hdr.uarea_addr,
		       dst_uarea_size <= src_uarea_size ? dst_uarea_size :
		       src_uarea_size);
	}

	copy_packet_parser_metadata(srchdr, dsthdr);

	/* Metadata copied, but return indication of whether the packet
	 * user area was truncated in the process. Note this can only
	 * happen when copying between different pools.
	 */
	return dst_uarea_size < src_uarea_size;
}

/* Simple implementation of ones complement sum.
 * Based on RFC1071 and its errata.
 */
typedef union {
	uint16_t w;
	uint8_t b[2];
} swap_buf_t;

static uint32_t segment_sum16_32(const uint8_t *p,
				 uint32_t len,
				 uint32_t offset)

{
	uint32_t sum = 0;

	/* Include second part of 16-bit short word split between segments */
	if (len > 0 && (offset % 2)) {
		swap_buf_t sw;

		sw.b[0] = 0;
		sw.b[1] = *p++;
		sum = sw.w;
		len--;
	}

	/*
	 * If pointer is 16-bit aligned, we can do fast path calculation.
	 * If it is not, we sum hi and lo bytes separately and then sum them.
	 */
	if ((uintptr_t)p % 2) {
		uint32_t sum1 = 0, sum2 = 0;

		while (len > 1) {
			sum1 += *p++;
			sum2 += *p++;
			len -= 2;
		}
#if (ODP_BYTE_ORDER == ODP_BIG_ENDIAN)
		sum += sum2 + (sum1 << 8);
#else
		sum += sum1 + (sum2 << 8);
#endif
	} else {
		while (len > 1) {
			sum += *(const uint16_t *)(uintptr_t)p;
			p += 2;
			len -= 2;
		}
	}

	/* Add left-over byte, if any */
	if (len > 0) {
		swap_buf_t sw;

		sw.b[0] = *p;
		sw.b[1] = 0;
		sum += sw.w;
	}

	return sum;
}

static uint32_t packet_sum16_32(odp_packet_hdr_t *pkt_hdr,
				uint32_t offset,
				uint32_t len)
{
	uint32_t sum = 0;

	if (offset + len > pkt_hdr->frame_len)
		return 0;

	while (len > 0) {
		uint32_t seglen = 0; /* GCC */
		void *mapaddr = packet_map(pkt_hdr, offset, &seglen, NULL);

		if (seglen > len)
			seglen = len;

		sum += segment_sum16_32(mapaddr, seglen, offset);
		len -= seglen;
		offset += seglen;
	}

	return sum;
}

static uint16_t packet_sum_ones_comp16(odp_packet_hdr_t *pkt_hdr,
				       uint32_t offset,
				       uint32_t len,
				       uint32_t l4_part_sum)
{
	uint32_t sum = l4_part_sum;

	sum += packet_sum16_32(pkt_hdr, offset, len);

	/* Not more than two additions */
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}

static uint32_t packet_sum_crc32c(odp_packet_hdr_t *pkt_hdr,
				  uint32_t offset,
				  uint32_t len,
				  uint32_t init_val)
{
	uint32_t sum = init_val;

	if (offset + len > pkt_hdr->frame_len)
		return sum;

	while (len > 0) {
		uint32_t seglen = 0; /* GCC */
		void *mapaddr = packet_map(pkt_hdr, offset, &seglen, NULL);

		if (seglen > len)
			seglen = len;

		sum = odp_hash_crc32c(mapaddr, seglen, sum);
		len -= seglen;
		offset += seglen;
	}

	return sum;
}

/** Parser helper function for Ethernet packets */
static inline uint16_t parse_eth(packet_parser_t *prs, const uint8_t **parseptr,
				 uint32_t *offset, uint32_t frame_len)
{
	uint16_t ethtype;
	const _odp_ethhdr_t *eth;
	uint16_t macaddr0, macaddr2, macaddr4;
	const _odp_vlanhdr_t *vlan;
	_odp_packet_input_flags_t input_flags;

	input_flags.all = 0;
	input_flags.l2  = 1;
	input_flags.eth = 1;

	eth = (const _odp_ethhdr_t *)*parseptr;

	/* Detect jumbo frames */
	if (odp_unlikely(frame_len > _ODP_ETH_LEN_MAX))
		input_flags.jumbo = 1;

	/* Handle Ethernet broadcast/multicast addresses */
	macaddr0 = odp_be_to_cpu_16(*((const uint16_t *)(const void *)eth));
	if (odp_unlikely((macaddr0 & 0x0100) == 0x0100))
		input_flags.eth_mcast = 1;

	if (odp_unlikely(macaddr0 == 0xffff)) {
		macaddr2 =
			odp_be_to_cpu_16(*((const uint16_t *)
					    (const void *)eth + 1));
		macaddr4 =
			odp_be_to_cpu_16(*((const uint16_t *)
					    (const void *)eth + 2));

		if ((macaddr2 == 0xffff) && (macaddr4 == 0xffff))
			input_flags.eth_bcast = 1;
	}

	/* Get Ethertype */
	ethtype = odp_be_to_cpu_16(eth->type);
	*offset += sizeof(*eth);
	*parseptr += sizeof(*eth);

	/* Check for SNAP vs. DIX */
	if (odp_unlikely(ethtype < _ODP_ETH_LEN_MAX)) {
		input_flags.snap = 1;
		if (ethtype > frame_len - *offset) {
			prs->flags.snap_len_err = 1;
			ethtype = 0;
			goto error;
		}
		ethtype = odp_be_to_cpu_16(*((const uint16_t *)(uintptr_t)
					      (parseptr + 6)));
		*offset   += 8;
		*parseptr += 8;
	}

	/* Parse the VLAN header(s), if present */
	if (odp_unlikely(ethtype == _ODP_ETHTYPE_VLAN_OUTER)) {
		input_flags.vlan_qinq = 1;
		input_flags.vlan = 1;

		vlan = (const _odp_vlanhdr_t *)*parseptr;
		ethtype = odp_be_to_cpu_16(vlan->type);
		*offset += sizeof(_odp_vlanhdr_t);
		*parseptr += sizeof(_odp_vlanhdr_t);
	}

	if (ethtype == _ODP_ETHTYPE_VLAN) {
		input_flags.vlan = 1;
		vlan = (const _odp_vlanhdr_t *)*parseptr;
		ethtype = odp_be_to_cpu_16(vlan->type);
		*offset += sizeof(_odp_vlanhdr_t);
		*parseptr += sizeof(_odp_vlanhdr_t);
	}

error:
	prs->input_flags.all |= input_flags.all;

	return ethtype;
}

/**
 * Parser helper function for IPv4
 */
static inline uint8_t parse_ipv4(packet_parser_t *prs, const uint8_t **parseptr,
				 uint32_t *offset, uint32_t frame_len,
				 odp_proto_chksums_t chksums,
				 uint32_t *l4_part_sum)
{
	const _odp_ipv4hdr_t *ipv4 = (const _odp_ipv4hdr_t *)*parseptr;
	uint32_t dstaddr = odp_be_to_cpu_32(ipv4->dst_addr);
	uint32_t l3_len = odp_be_to_cpu_16(ipv4->tot_len);
	uint16_t frag_offset = odp_be_to_cpu_16(ipv4->frag_offset);
	uint8_t ver = _ODP_IPV4HDR_VER(ipv4->ver_ihl);
	uint8_t ihl = _ODP_IPV4HDR_IHL(ipv4->ver_ihl);

	if (odp_unlikely(ihl < _ODP_IPV4HDR_IHL_MIN ||
			 ver != 4 ||
			 (l3_len > frame_len - *offset))) {
		prs->flags.ip_err = 1;
		return 0;
	}

	if (chksums.chksum.ipv4) {
		prs->input_flags.l3_chksum_done = 1;
		if (odp_chksum_ones_comp16(ipv4, ihl * 4) != 0xffff) {
			prs->flags.ip_err = 1;
			prs->flags.l3_chksum_err = 1;
			return 0;
		}
	}

	*offset   += ihl * 4;
	*parseptr += ihl * 4;

	if (chksums.chksum.udp || chksums.chksum.tcp)
		*l4_part_sum = segment_sum16_32((const uint8_t *)&ipv4->src_addr,
						2 * _ODP_IPV4ADDR_LEN, 0);

	if (odp_unlikely(ihl > _ODP_IPV4HDR_IHL_MIN))
		prs->input_flags.ipopt = 1;

	/* A packet is a fragment if:
	*  "more fragments" flag is set (all fragments except the last)
	*     OR
	*  "fragment offset" field is nonzero (all fragments except the first)
	*/
	if (odp_unlikely(_ODP_IPV4HDR_IS_FRAGMENT(frag_offset)))
		prs->input_flags.ipfrag = 1;

	/* Handle IPv4 broadcast / multicast */
	if (odp_unlikely(dstaddr == 0xffffffff))
		prs->input_flags.ip_bcast = 1;

	if (odp_unlikely((dstaddr >> 28) == 0xe))
		prs->input_flags.ip_mcast = 1;

	return ipv4->proto;
}

/**
 * Parser helper function for IPv6
 */
static inline uint8_t parse_ipv6(packet_parser_t *prs, const uint8_t **parseptr,
				 uint32_t *offset, uint32_t frame_len,
				 uint32_t seg_len,
				 odp_proto_chksums_t chksums,
				 uint32_t *l4_part_sum)
{
	const _odp_ipv6hdr_t *ipv6 = (const _odp_ipv6hdr_t *)*parseptr;
	const _odp_ipv6hdr_ext_t *ipv6ext;
	uint32_t dstaddr0 = odp_be_to_cpu_32(ipv6->dst_addr.u8[0]);
	uint32_t l3_len = odp_be_to_cpu_16(ipv6->payload_len) +
			  _ODP_IPV6HDR_LEN;

	/* Basic sanity checks on IPv6 header */
	if ((odp_be_to_cpu_32(ipv6->ver_tc_flow) >> 28) != 6 ||
	    l3_len > frame_len - *offset) {
		prs->flags.ip_err = 1;
		return 0;
	}

	/* IPv6 broadcast / multicast flags */
	prs->input_flags.ip_mcast = (dstaddr0 & 0xff000000) == 0xff000000;
	prs->input_flags.ip_bcast = 0;

	/* Skip past IPv6 header */
	*offset   += sizeof(_odp_ipv6hdr_t);
	*parseptr += sizeof(_odp_ipv6hdr_t);

	if (chksums.chksum.udp || chksums.chksum.tcp)
		*l4_part_sum = segment_sum16_32((const uint8_t *)&ipv6->src_addr,
						2 * _ODP_IPV6ADDR_LEN, 0);

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
			prs->flags.ip_err = 1;
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
static inline void parse_tcp(packet_parser_t *prs, const uint8_t **parseptr,
			     uint16_t tcp_len,
			     odp_proto_chksums_t chksums,
			     uint32_t *l4_part_sum)
{
	const _odp_tcphdr_t *tcp = (const _odp_tcphdr_t *)*parseptr;
	uint32_t len = tcp->hl * 4;

	if (odp_unlikely(tcp->hl < sizeof(_odp_tcphdr_t) / sizeof(uint32_t)))
		prs->flags.tcp_err = 1;

	if (chksums.chksum.tcp &&
	    !prs->input_flags.ipfrag) {
		*l4_part_sum += odp_cpu_to_be_16(tcp_len);
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
		*l4_part_sum += _ODP_IPPROTO_TCP;
#else
		*l4_part_sum += _ODP_IPPROTO_TCP << 8;
#endif
	}

	*parseptr += len;
}

/**
 * Parser helper function for UDP
 */
static inline void parse_udp(packet_parser_t *prs, const uint8_t **parseptr,
			     odp_proto_chksums_t chksums,
			     uint32_t *l4_part_sum)
{
	const _odp_udphdr_t *udp = (const _odp_udphdr_t *)*parseptr;
	uint32_t udplen = odp_be_to_cpu_16(udp->length);
	uint16_t ipsec_port = odp_cpu_to_be_16(_ODP_UDP_IPSEC_PORT);

	if (odp_unlikely(udplen < sizeof(_odp_udphdr_t))) {
		prs->flags.udp_err = 1;
		return;
	}

	if (chksums.chksum.udp &&
	    !prs->input_flags.ipfrag) {
		if (udp->chksum == 0) {
			prs->input_flags.l4_chksum_done = 1;
			prs->flags.l4_chksum_err =
				(prs->input_flags.ipv4 != 1);
		} else {
			*l4_part_sum += udp->length;
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
			*l4_part_sum += _ODP_IPPROTO_UDP;
#else
			*l4_part_sum += _ODP_IPPROTO_UDP << 8;
#endif
		}
		prs->input_flags.udp_chksum_zero = (udp->chksum == 0);
	}

	if (odp_unlikely(ipsec_port == udp->dst_port && udplen > 4)) {
		uint32_t val;

		memcpy(&val, udp + 1, 4);
		if (val != 0) {
			prs->input_flags.ipsec = 1;
			prs->input_flags.ipsec_udp = 1;
		}
	}

	*parseptr += sizeof(_odp_udphdr_t);
}

/**
 * Parser helper function for SCTP
 */
static inline void parse_sctp(packet_parser_t *prs, const uint8_t **parseptr,
			      uint16_t sctp_len,
			      odp_proto_chksums_t chksums,
			      uint32_t *l4_part_sum)
{
	if (odp_unlikely(sctp_len < sizeof(_odp_sctphdr_t))) {
		prs->flags.sctp_err = 1;
		return;
	}

	if (chksums.chksum.sctp &&
	    !prs->input_flags.ipfrag) {
		const _odp_sctphdr_t *sctp =
			(const _odp_sctphdr_t *)*parseptr;
		uint32_t crc = ~0;
		uint32_t zero = 0;

		crc = odp_hash_crc32c(sctp, sizeof(*sctp) - 4, crc);
		crc = odp_hash_crc32c(&zero, 4, crc);
		*l4_part_sum = crc;
	}

	*parseptr += sizeof(_odp_sctphdr_t);
}

static inline
int packet_parse_common_l3_l4(packet_parser_t *prs, const uint8_t *parseptr,
			      uint32_t offset,
			      uint32_t frame_len, uint32_t seg_len,
			      int layer, uint16_t ethtype,
			      odp_proto_chksums_t chksums,
			      uint32_t *l4_part_sum)
{
	uint8_t  ip_proto;

	prs->l3_offset = offset;

	if (odp_unlikely(layer <= ODP_PROTO_LAYER_L2))
		return prs->flags.all.error != 0;

	/* Set l3 flag only for known ethtypes */
	prs->input_flags.l3 = 1;

	/* Parse Layer 3 headers */
	switch (ethtype) {
	case _ODP_ETHTYPE_IPV4:
		prs->input_flags.ipv4 = 1;
		ip_proto = parse_ipv4(prs, &parseptr, &offset, frame_len,
				      chksums, l4_part_sum);
		prs->l4_offset = offset;
		break;

	case _ODP_ETHTYPE_IPV6:
		prs->input_flags.ipv6 = 1;
		ip_proto = parse_ipv6(prs, &parseptr, &offset, frame_len,
				      seg_len, chksums, l4_part_sum);
		prs->l4_offset = offset;
		break;

	case _ODP_ETHTYPE_ARP:
		prs->input_flags.arp = 1;
		ip_proto = 255;  /* Reserved invalid by IANA */
		break;

	default:
		prs->input_flags.l3 = 0;
		ip_proto = 255;  /* Reserved invalid by IANA */
	}

	if (layer == ODP_PROTO_LAYER_L3)
		return prs->flags.all.error != 0;

	/* Set l4 flag only for known ip_proto */
	prs->input_flags.l4 = 1;

	/* Parse Layer 4 headers */
	switch (ip_proto) {
	case _ODP_IPPROTO_ICMPV4:
	/* Fall through */

	case _ODP_IPPROTO_ICMPV6:
		prs->input_flags.icmp = 1;
		break;

	case _ODP_IPPROTO_IPIP:
		/* Do nothing */
		break;

	case _ODP_IPPROTO_TCP:
		if (odp_unlikely(offset + _ODP_TCPHDR_LEN > seg_len))
			return -1;
		prs->input_flags.tcp = 1;
		parse_tcp(prs, &parseptr, frame_len - prs->l4_offset, chksums,
			  l4_part_sum);
		break;

	case _ODP_IPPROTO_UDP:
		if (odp_unlikely(offset + _ODP_UDPHDR_LEN > seg_len))
			return -1;
		prs->input_flags.udp = 1;
		parse_udp(prs, &parseptr, chksums, l4_part_sum);
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
		parse_sctp(prs, &parseptr, frame_len - prs->l4_offset, chksums,
			   l4_part_sum);
		break;

	case _ODP_IPPROTO_NO_NEXT:
		prs->input_flags.no_next_hdr = 1;
		break;

	default:
		prs->input_flags.l4 = 0;
		break;
	}

	return prs->flags.all.error != 0;
}

/**
 * Parse common packet headers up to given layer
 *
 * The function expects at least PACKET_PARSE_SEG_LEN bytes of data to be
 * available from the ptr. Also parse metadata must be already initialized.
 */
int packet_parse_common(packet_parser_t *prs, const uint8_t *ptr,
			uint32_t frame_len, uint32_t seg_len,
			int layer, odp_proto_chksums_t chksums)
{
	uint32_t offset;
	uint16_t ethtype;
	const uint8_t *parseptr;
	uint32_t l4_part_sum;

	parseptr = ptr;
	offset = 0;

	if (odp_unlikely(layer == ODP_PROTO_LAYER_NONE))
		return 0;

	/* Assume valid L2 header, no CRC/FCS check in SW */
	prs->l2_offset = offset;

	ethtype = parse_eth(prs, &parseptr, &offset, frame_len);

	return packet_parse_common_l3_l4(prs, parseptr, offset, frame_len,
					 seg_len, layer, ethtype, chksums,
					 &l4_part_sum);
}

static inline int packet_ipv4_chksum(odp_packet_t pkt,
				     uint32_t offset,
				     _odp_ipv4hdr_t *ip,
				     odp_u16sum_t *chksum)
{
	unsigned int nleft = _ODP_IPV4HDR_IHL(ip->ver_ihl) * 4;
	uint16_t buf[nleft / 2];
	int res;

	if (odp_unlikely(nleft < sizeof(*ip)))
		return -1;
	ip->chksum = 0;
	memcpy(buf, ip, sizeof(*ip));
	res = odp_packet_copy_to_mem(pkt, offset + sizeof(*ip),
				     nleft - sizeof(*ip),
				     buf + sizeof(*ip) / 2);
	if (odp_unlikely(res < 0))
		return res;

	*chksum = ~odp_chksum_ones_comp16(buf, nleft);

	return 0;
}

#define _ODP_IPV4HDR_CSUM_OFFSET ODP_OFFSETOF(_odp_ipv4hdr_t, chksum)
#define _ODP_IPV4ADDR_OFFSSET ODP_OFFSETOF(_odp_ipv4hdr_t, src_addr)
#define _ODP_IPV6ADDR_OFFSSET ODP_OFFSETOF(_odp_ipv6hdr_t, src_addr)
#define _ODP_IPV4HDR_CSUM_OFFSET ODP_OFFSETOF(_odp_ipv4hdr_t, chksum)
#define _ODP_UDP_LEN_OFFSET ODP_OFFSETOF(_odp_udphdr_t, length)
#define _ODP_UDP_CSUM_OFFSET ODP_OFFSETOF(_odp_udphdr_t, chksum)

/**
 * Calculate and fill in IPv4 checksum
 *
 * @param pkt  ODP packet
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_packet_ipv4_chksum_insert(odp_packet_t pkt)
{
	uint32_t offset;
	_odp_ipv4hdr_t ip;
	odp_u16sum_t chksum;
	int res;

	offset = odp_packet_l3_offset(pkt);
	if (offset == ODP_PACKET_OFFSET_INVALID)
		return -1;

	res = odp_packet_copy_to_mem(pkt, offset, sizeof(ip), &ip);
	if (odp_unlikely(res < 0))
		return res;

	res = packet_ipv4_chksum(pkt, offset, &ip, &chksum);
	if (odp_unlikely(res < 0))
		return res;

	return odp_packet_copy_from_mem(pkt,
					offset + _ODP_IPV4HDR_CSUM_OFFSET,
					2, &chksum);
}

static int _odp_packet_tcp_udp_chksum_insert(odp_packet_t pkt, uint16_t proto)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	uint32_t zero = 0;
	uint32_t sum;
	uint16_t l3_ver;
	uint16_t chksum;
	uint32_t chksum_offset;

	if (pkt_hdr->p.l3_offset == ODP_PACKET_OFFSET_INVALID)
		return -1;
	if (pkt_hdr->p.l4_offset == ODP_PACKET_OFFSET_INVALID)
		return -1;

	odp_packet_copy_to_mem(pkt, pkt_hdr->p.l3_offset, 2, &l3_ver);

	if (_ODP_IPV4HDR_VER(l3_ver) == _ODP_IPV4)
		sum = packet_sum16_32(pkt_hdr,
				      pkt_hdr->p.l3_offset +
				      _ODP_IPV4ADDR_OFFSSET,
				      2 * _ODP_IPV4ADDR_LEN);
	else
		sum = packet_sum16_32(pkt_hdr,
				      pkt_hdr->p.l3_offset +
				      _ODP_IPV6ADDR_OFFSSET,
				      2 * _ODP_IPV6ADDR_LEN);
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
	sum += proto;
#else
	sum += proto << 8;
#endif

	if (proto == _ODP_IPPROTO_TCP) {
		sum += odp_cpu_to_be_16(pkt_hdr->frame_len -
					 pkt_hdr->p.l4_offset);
		chksum_offset = pkt_hdr->p.l4_offset + _ODP_UDP_CSUM_OFFSET;
	} else {
		sum += packet_sum16_32(pkt_hdr,
				       pkt_hdr->p.l4_offset +
				       _ODP_UDP_LEN_OFFSET,
				       2);
		chksum_offset = pkt_hdr->p.l4_offset + _ODP_UDP_CSUM_OFFSET;
	}
	odp_packet_copy_from_mem(pkt, chksum_offset, 2, &zero);

	sum += packet_sum16_32(pkt_hdr,
			       pkt_hdr->p.l4_offset,
			       pkt_hdr->frame_len -
			       pkt_hdr->p.l4_offset);

	/* Not more than two additions */
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	chksum = ~sum;

	if (proto == _ODP_IPPROTO_UDP && chksum == 0)
		chksum = 0xffff;

	return odp_packet_copy_from_mem(pkt,
					chksum_offset,
					2, &chksum);
}

/**
 * Calculate and fill in TCP checksum
 *
 * @param pkt  ODP packet
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_packet_tcp_chksum_insert(odp_packet_t pkt)
{
	return _odp_packet_tcp_udp_chksum_insert(pkt, _ODP_IPPROTO_TCP);
}

/**
 * Calculate and fill in UDP checksum
 *
 * @param pkt  ODP packet
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_packet_udp_chksum_insert(odp_packet_t pkt)
{
	return _odp_packet_tcp_udp_chksum_insert(pkt, _ODP_IPPROTO_UDP);
}

/**
 * Calculate and fill in SCTP checksum
 *
 * @param pkt  ODP packet
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_packet_sctp_chksum_insert(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	uint32_t sum;

	if (pkt_hdr->p.l4_offset == ODP_PACKET_OFFSET_INVALID)
		return -1;

	sum = 0;
	odp_packet_copy_from_mem(pkt, pkt_hdr->p.l4_offset + 8, 4, &sum);
	sum = ~packet_sum_crc32c(pkt_hdr, pkt_hdr->p.l4_offset,
				 pkt_hdr->frame_len - pkt_hdr->p.l4_offset,
				 ~0);
	return odp_packet_copy_from_mem(pkt, pkt_hdr->p.l4_offset + 8, 4, &sum);
}

static int packet_l4_chksum(odp_packet_hdr_t *pkt_hdr,
			    odp_proto_chksums_t chksums,
			    uint32_t l4_part_sum)
{
	/* UDP chksum == 0 case is covered in parse_udp() */
	if (chksums.chksum.udp &&
	    pkt_hdr->p.input_flags.udp &&
	    !pkt_hdr->p.input_flags.ipfrag &&
	    !pkt_hdr->p.input_flags.udp_chksum_zero) {
		uint16_t sum = ~packet_sum_ones_comp16(pkt_hdr,
						       pkt_hdr->p.l4_offset,
						       pkt_hdr->frame_len -
						       pkt_hdr->p.l4_offset,
						       l4_part_sum);

		pkt_hdr->p.input_flags.l4_chksum_done = 1;
		if (sum != 0) {
			pkt_hdr->p.flags.l4_chksum_err = 1;
			pkt_hdr->p.flags.udp_err = 1;
			ODP_DBG("UDP chksum fail (%x)!\n", sum);
		}
	}

	if (chksums.chksum.tcp &&
	    pkt_hdr->p.input_flags.tcp &&
	    !pkt_hdr->p.input_flags.ipfrag) {
		uint16_t sum = ~packet_sum_ones_comp16(pkt_hdr,
						       pkt_hdr->p.l4_offset,
						       pkt_hdr->frame_len -
						       pkt_hdr->p.l4_offset,
						       l4_part_sum);

		pkt_hdr->p.input_flags.l4_chksum_done = 1;
		if (sum != 0) {
			pkt_hdr->p.flags.l4_chksum_err = 1;
			pkt_hdr->p.flags.tcp_err = 1;
			ODP_DBG("TCP chksum fail (%x)!\n", sum);
		}
	}

	if (chksums.chksum.sctp &&
	    pkt_hdr->p.input_flags.sctp &&
	    !pkt_hdr->p.input_flags.ipfrag) {
		uint32_t sum = ~packet_sum_crc32c(pkt_hdr,
						 pkt_hdr->p.l4_offset +
						 _ODP_SCTPHDR_LEN,
						 pkt_hdr->frame_len -
						 pkt_hdr->p.l4_offset -
						 _ODP_SCTPHDR_LEN,
						 l4_part_sum);
		_odp_sctphdr_t *sctp = packet_map(pkt_hdr,
						  pkt_hdr->p.l4_offset,
						  NULL, NULL);

		pkt_hdr->p.input_flags.l4_chksum_done = 1;
		if (sum != sctp->chksum) {
			pkt_hdr->p.flags.l4_chksum_err = 1;
			pkt_hdr->p.flags.sctp_err = 1;
			ODP_DBG("SCTP chksum fail (%x/%x)!\n", sum,
				sctp->chksum);
		}
	}

	return pkt_hdr->p.flags.all_flags != 0;
}

/**
 * Simple packet parser
 */
int packet_parse_layer(odp_packet_hdr_t *pkt_hdr,
		       odp_proto_layer_t layer,
		       odp_proto_chksums_t chksums)
{
	uint32_t seg_len = packet_first_seg_len(pkt_hdr);
	const uint8_t *base = packet_data(pkt_hdr);
	uint32_t offset = 0;
	uint16_t ethtype;
	uint32_t l4_part_sum = 0;
	int rc;

	if (odp_unlikely(layer == ODP_PROTO_LAYER_NONE))
		return 0;

	/* Assume valid L2 header, no CRC/FCS check in SW */
	pkt_hdr->p.l2_offset = offset;

	ethtype = parse_eth(&pkt_hdr->p, &base, &offset, pkt_hdr->frame_len);

	rc = packet_parse_common_l3_l4(&pkt_hdr->p, base, offset,
				       pkt_hdr->frame_len,
				       seg_len, layer, ethtype, chksums,
				       &l4_part_sum);

	if (rc != 0)
		return rc;

	if (layer >= ODP_PKTIO_PARSER_LAYER_L4)
		return packet_l4_chksum(pkt_hdr, chksums, l4_part_sum);
	else
		return 0;
}

int odp_packet_parse(odp_packet_t pkt, uint32_t offset,
		     const odp_packet_parse_param_t *param)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	const uint8_t *data;
	uint32_t seg_len;
	uint32_t packet_len = pkt_hdr->frame_len;
	odp_proto_t proto = param->proto;
	odp_proto_layer_t layer = param->last_layer;
	int ret;
	uint16_t ethtype;
	uint32_t l4_part_sum = 0;

	if (proto == ODP_PROTO_NONE || layer == ODP_PROTO_LAYER_NONE)
		return -1;

	data = packet_map(pkt_hdr, offset, &seg_len, NULL);

	if (data == NULL)
		return -1;

	packet_parse_reset(pkt_hdr);

	if (proto == ODP_PROTO_ETH) {
		/* Assume valid L2 header, no CRC/FCS check in SW */
		pkt_hdr->p.l2_offset = offset;

		ethtype = parse_eth(&pkt_hdr->p, &data, &offset, packet_len);
	} else if (proto == ODP_PROTO_IPV4) {
		ethtype = _ODP_ETHTYPE_IPV4;
	} else if (proto == ODP_PROTO_IPV6) {
		ethtype = _ODP_ETHTYPE_IPV6;
	} else {
		ethtype = 0; /* Invalid */
	}

	ret = packet_parse_common_l3_l4(&pkt_hdr->p, data, offset,
					packet_len, seg_len,
					layer, ethtype,
					param->chksums,
					&l4_part_sum);

	if (ret)
		return -1;

	if (layer >= ODP_PROTO_LAYER_L4) {
		ret = packet_l4_chksum(pkt_hdr, param->chksums, l4_part_sum);
		if (ret)
			return -1;
	}

	return 0;
}

int odp_packet_parse_multi(const odp_packet_t pkt[], const uint32_t offset[],
			   int num, const odp_packet_parse_param_t *param)
{
	int i;

	for (i = 0; i < num; i++)
		if (odp_packet_parse(pkt[i], offset[i], param))
			return i;

	return num;
}

void odp_packet_parse_result(odp_packet_t pkt,
			     odp_packet_parse_result_t *result)
{
	/* TODO: optimize to single word copy when packet header stores bits
	 * directly into odp_packet_parse_result_flag_t */
	result->flag.all           = 0;
	result->flag.has_error     = odp_packet_has_error(pkt);
	result->flag.has_l2_error  = odp_packet_has_l2_error(pkt);
	result->flag.has_l3_error  = odp_packet_has_l3_error(pkt);
	result->flag.has_l4_error  = odp_packet_has_l4_error(pkt);
	result->flag.has_l2        = odp_packet_has_l2(pkt);
	result->flag.has_l3        = odp_packet_has_l3(pkt);
	result->flag.has_l4        = odp_packet_has_l4(pkt);
	result->flag.has_eth       = odp_packet_has_eth(pkt);
	result->flag.has_eth_bcast = odp_packet_has_eth_bcast(pkt);
	result->flag.has_eth_mcast = odp_packet_has_eth_mcast(pkt);
	result->flag.has_jumbo     = odp_packet_has_jumbo(pkt);
	result->flag.has_vlan      = odp_packet_has_vlan(pkt);
	result->flag.has_vlan_qinq = odp_packet_has_vlan_qinq(pkt);
	result->flag.has_arp       = odp_packet_has_arp(pkt);
	result->flag.has_ipv4      = odp_packet_has_ipv4(pkt);
	result->flag.has_ipv6      = odp_packet_has_ipv6(pkt);
	result->flag.has_ip_bcast  = odp_packet_has_ip_bcast(pkt);
	result->flag.has_ip_mcast  = odp_packet_has_ip_mcast(pkt);
	result->flag.has_ipfrag    = odp_packet_has_ipfrag(pkt);
	result->flag.has_ipopt     = odp_packet_has_ipopt(pkt);
	result->flag.has_ipsec     = odp_packet_has_ipsec(pkt);
	result->flag.has_udp       = odp_packet_has_udp(pkt);
	result->flag.has_tcp       = odp_packet_has_tcp(pkt);
	result->flag.has_sctp      = odp_packet_has_sctp(pkt);
	result->flag.has_icmp      = odp_packet_has_icmp(pkt);

	result->packet_len       = odp_packet_len(pkt);
	result->l2_offset        = odp_packet_l2_offset(pkt);
	result->l3_offset        = odp_packet_l3_offset(pkt);
	result->l4_offset        = odp_packet_l4_offset(pkt);
	result->l3_chksum_status = odp_packet_l3_chksum_status(pkt);
	result->l4_chksum_status = odp_packet_l4_chksum_status(pkt);
	result->l2_type          = odp_packet_l2_type(pkt);
	result->l3_type          = odp_packet_l3_type(pkt);
	result->l4_type          = odp_packet_l4_type(pkt);
}

void odp_packet_parse_result_multi(const odp_packet_t pkt[],
				   odp_packet_parse_result_t *result[],
				   int num)
{
	int i;

	for (i = 0; i < num; i++)
		odp_packet_parse_result(pkt[i], result[i]);
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
	odp_packet_t new;
	int ret;

	new = odp_packet_copy(pkt, odp_packet_pool(pkt));

	if (new == ODP_PACKET_INVALID) {
		ODP_ERR("copy failed\n");
		return ODP_PACKET_INVALID;
	}

	ret = odp_packet_trunc_head(&new, offset, NULL, NULL);

	if (ret < 0) {
		ODP_ERR("trunk_head failed\n");
		odp_packet_free(new);
		return ODP_PACKET_INVALID;
	}

	return new;
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
	odp_buffer_hdr_t *buf_hdr;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	uint32_t ref_cnt;

	while (pkt_hdr != NULL) {
		buf_hdr = &pkt_hdr->buf_hdr;

		ref_cnt = buffer_ref(buf_hdr);

		if (is_multi_ref(ref_cnt))
			return 1;

		pkt_hdr = pkt_hdr->seg_next;
	}

	return 0;
}

odp_proto_l2_type_t odp_packet_l2_type(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (pkt_hdr->p.input_flags.eth)
		return ODP_PROTO_L2_TYPE_ETH;

	return ODP_PROTO_L2_TYPE_NONE;
}

odp_proto_l3_type_t odp_packet_l3_type(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (pkt_hdr->p.input_flags.ipv4)
		return ODP_PROTO_L3_TYPE_IPV4;
	else if (pkt_hdr->p.input_flags.ipv6)
		return ODP_PROTO_L3_TYPE_IPV6;
	else if (pkt_hdr->p.input_flags.arp)
		return ODP_PROTO_L3_TYPE_ARP;

	return ODP_PROTO_L3_TYPE_NONE;
}

odp_proto_l4_type_t odp_packet_l4_type(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (pkt_hdr->p.input_flags.tcp)
		return ODP_PROTO_L4_TYPE_TCP;
	else if (pkt_hdr->p.input_flags.udp)
		return ODP_PROTO_L4_TYPE_UDP;
	else if (pkt_hdr->p.input_flags.sctp)
		return ODP_PROTO_L4_TYPE_SCTP;
	else if (pkt_hdr->p.input_flags.ipsec_ah)
		return ODP_PROTO_L4_TYPE_AH;
	else if (pkt_hdr->p.input_flags.ipsec_esp)
		return ODP_PROTO_L4_TYPE_ESP;
	else if (pkt_hdr->p.input_flags.icmp &&
		 pkt_hdr->p.input_flags.ipv4)
		return ODP_PROTO_L4_TYPE_ICMPV4;
	else if (pkt_hdr->p.input_flags.icmp &&
		 pkt_hdr->p.input_flags.ipv6)
		return ODP_PROTO_L4_TYPE_ICMPV6;
	else if (pkt_hdr->p.input_flags.no_next_hdr)
		return ODP_PROTO_L4_TYPE_NO_NEXT;

	return ODP_PROTO_L4_TYPE_NONE;
}
