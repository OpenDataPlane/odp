/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/packet.h>
#include <odp_packet_internal.h>
#include <odp_debug_internal.h>
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

static inline odp_packet_t packet_handle(odp_packet_hdr_t *pkt_hdr)
{
	return (odp_packet_t)pkt_hdr->buf_hdr.handle.handle;
}

static inline odp_buffer_t buffer_handle(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->buf_hdr.handle.handle;
}

static inline uint32_t packet_seg_len(odp_packet_hdr_t *pkt_hdr,
				      uint32_t seg_idx)
{
	return pkt_hdr->buf_hdr.seg[seg_idx].len;
}

static inline void *packet_seg_data(odp_packet_hdr_t *pkt_hdr, uint32_t seg_idx)
{
	return pkt_hdr->buf_hdr.seg[seg_idx].data;
}

static inline int packet_last_seg(odp_packet_hdr_t *pkt_hdr)
{
	if (CONFIG_PACKET_MAX_SEGS == 1)
		return 0;
	else
		return pkt_hdr->buf_hdr.segcount - 1;
}

static inline uint32_t packet_first_seg_len(odp_packet_hdr_t *pkt_hdr)
{
	return packet_seg_len(pkt_hdr, 0);
}

static inline uint32_t packet_last_seg_len(odp_packet_hdr_t *pkt_hdr)
{
	int last = packet_last_seg(pkt_hdr);

	return packet_seg_len(pkt_hdr, last);
}

static inline void *packet_data(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->buf_hdr.seg[0].data;
}

static inline void *packet_tail(odp_packet_hdr_t *pkt_hdr)
{
	int last = packet_last_seg(pkt_hdr);
	uint32_t seg_len = pkt_hdr->buf_hdr.seg[last].len;

	return pkt_hdr->buf_hdr.seg[last].data + seg_len;
}

static inline uint32_t seg_tailroom(odp_packet_hdr_t *pkt_hdr, int seg)
{
	uint32_t seg_len      = pkt_hdr->buf_hdr.seg[seg].len;
	odp_buffer_hdr_t *hdr = pkt_hdr->buf_hdr.seg[seg].hdr;
	uint8_t *tail         = pkt_hdr->buf_hdr.seg[seg].data + seg_len;

	return hdr->buf_end - tail;
}

static inline void push_head(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	pkt_hdr->headroom  -= len;
	pkt_hdr->frame_len += len;
	pkt_hdr->buf_hdr.seg[0].data -= len;
	pkt_hdr->buf_hdr.seg[0].len  += len;
}

static inline void pull_head(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	pkt_hdr->headroom  += len;
	pkt_hdr->frame_len -= len;
	pkt_hdr->buf_hdr.seg[0].data += len;
	pkt_hdr->buf_hdr.seg[0].len  -= len;
}

static inline void push_tail(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	int last = packet_last_seg(pkt_hdr);

	pkt_hdr->tailroom  -= len;
	pkt_hdr->frame_len += len;
	pkt_hdr->buf_hdr.seg[last].len += len;
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
	dst->op_result = src->op_result;

	/* buffer header side packet metadata */
	dst->buf_hdr.buf_u64    = src->buf_hdr.buf_u64;
	dst->buf_hdr.uarea_addr = src->buf_hdr.uarea_addr;
	dst->buf_hdr.uarea_size = src->buf_hdr.uarea_size;

	/* segmentation data is not copied:
	 *   buf_hdr.seg[]
	 *   buf_hdr.segcount
	 */
}

static inline void *packet_map(odp_packet_hdr_t *pkt_hdr,
			       uint32_t offset, uint32_t *seg_len, int *seg_idx)
{
	void *addr;
	uint32_t len;
	int seg = 0;
	int seg_count = pkt_hdr->buf_hdr.segcount;

	if (odp_unlikely(offset >= pkt_hdr->frame_len))
		return NULL;

	if (odp_likely(CONFIG_PACKET_MAX_SEGS == 1 || seg_count == 1)) {
		addr = pkt_hdr->buf_hdr.seg[0].data + offset;
		len  = pkt_hdr->buf_hdr.seg[0].len - offset;
	} else {
		int i;
		uint32_t seg_start = 0, seg_end = 0;

		for (i = 0; i < seg_count; i++) {
			seg_end += pkt_hdr->buf_hdr.seg[i].len;

			if (odp_likely(offset < seg_end))
				break;

			seg_start = seg_end;
		}

		addr = pkt_hdr->buf_hdr.seg[i].data + (offset - seg_start);
		len  = pkt_hdr->buf_hdr.seg[i].len - (offset - seg_start);
		seg  = i;
	}

	if (seg_len)
		*seg_len = len;

	if (seg_idx)
		*seg_idx = seg;

	return addr;
}

static inline void packet_parse_disable(odp_packet_hdr_t *pkt_hdr)
{
	pkt_hdr->p.input_flags.parsed_l2  = 1;
	pkt_hdr->p.parsed_layers = LAYER_ALL;
}

void packet_parse_reset(odp_packet_hdr_t *pkt_hdr)
{
	/* Reset parser metadata before new parse */
	pkt_hdr->p.parsed_layers    = LAYER_NONE;
	pkt_hdr->p.error_flags.all  = 0;
	pkt_hdr->p.input_flags.all  = 0;
	pkt_hdr->p.output_flags.all = 0;
	pkt_hdr->p.l2_offset        = 0;
	pkt_hdr->p.l3_offset        = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->p.l4_offset        = ODP_PACKET_OFFSET_INVALID;
}

/**
 * Initialize packet
 */
static inline void packet_init(odp_packet_hdr_t *pkt_hdr, uint32_t len,
			       int parse)
{
	uint32_t seg_len;
	int num = pkt_hdr->buf_hdr.segcount;

	if (odp_likely(CONFIG_PACKET_MAX_SEGS == 1 || num == 1)) {
		seg_len = len;
		pkt_hdr->buf_hdr.seg[0].len = len;
	} else {
		seg_len = len - ((num - 1) * CONFIG_PACKET_MAX_SEG_LEN);

		/* Last segment data length */
		pkt_hdr->buf_hdr.seg[num - 1].len = seg_len;
	}

	pkt_hdr->p.parsed_layers    = LAYER_NONE;
	pkt_hdr->p.input_flags.all  = 0;
	pkt_hdr->p.output_flags.all = 0;
	pkt_hdr->p.error_flags.all  = 0;

	pkt_hdr->p.l2_offset = 0;
	pkt_hdr->p.l3_offset = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->p.l4_offset = ODP_PACKET_OFFSET_INVALID;

	/* Disable lazy parsing on user allocated packets */
	if (!parse)
		packet_parse_disable(pkt_hdr);

       /*
	* Packet headroom is set from the pool's headroom
	* Packet tailroom is rounded up to fill the last
	* segment occupied by the allocated length.
	*/
	pkt_hdr->frame_len = len;
	pkt_hdr->headroom  = CONFIG_PACKET_HEADROOM;
	pkt_hdr->tailroom  = CONFIG_PACKET_MAX_SEG_LEN - seg_len +
			     CONFIG_PACKET_TAILROOM;

	pkt_hdr->input = ODP_PKTIO_INVALID;
}

static inline odp_packet_hdr_t *init_segments(odp_buffer_t buf[], int num)
{
	odp_packet_hdr_t *pkt_hdr;
	int i;

	/* First buffer is the packet descriptor */
	pkt_hdr = odp_packet_hdr((odp_packet_t)buf[0]);

	pkt_hdr->buf_hdr.seg[0].data = pkt_hdr->buf_hdr.base_data;
	pkt_hdr->buf_hdr.seg[0].len  = pkt_hdr->buf_hdr.base_len;

	/* Link segments */
	if (odp_unlikely(CONFIG_PACKET_MAX_SEGS != 1)) {
		pkt_hdr->buf_hdr.segcount = num;

		if (odp_unlikely(num > 1)) {
			for (i = 1; i < num; i++) {
				odp_packet_hdr_t *hdr;
				odp_buffer_hdr_t *b_hdr;

				hdr   = odp_packet_hdr((odp_packet_t)buf[i]);
				b_hdr = &hdr->buf_hdr;

				pkt_hdr->buf_hdr.seg[i].hdr  = hdr;
				pkt_hdr->buf_hdr.seg[i].data = b_hdr->base_data;
				pkt_hdr->buf_hdr.seg[i].len  = b_hdr->base_len;
			}
		}
	}

	return pkt_hdr;
}

/* Calculate the number of segments */
static inline int num_segments(uint32_t len)
{
	uint32_t max_seg_len;
	int num;

	if (CONFIG_PACKET_MAX_SEGS == 1)
		return 1;

	num = 1;
	max_seg_len = CONFIG_PACKET_MAX_SEG_LEN;

	if (odp_unlikely(len > max_seg_len)) {
		num = len / max_seg_len;

		if (odp_likely((num * max_seg_len) != len))
			num += 1;
	}

	return num;
}

static inline void copy_all_segs(odp_packet_hdr_t *to, odp_packet_hdr_t *from)
{
	int i;
	int n   = to->buf_hdr.segcount;
	int num = from->buf_hdr.segcount;

	for (i = 0; i < num; i++) {
		to->buf_hdr.seg[n + i].hdr  = from->buf_hdr.seg[i].hdr;
		to->buf_hdr.seg[n + i].data = from->buf_hdr.seg[i].data;
		to->buf_hdr.seg[n + i].len  = from->buf_hdr.seg[i].len;
	}

	to->buf_hdr.segcount = n + num;
}

static inline void copy_num_segs(odp_packet_hdr_t *to, odp_packet_hdr_t *from,
				 int num)
{
	int i;

	for (i = 0; i < num; i++) {
		to->buf_hdr.seg[i].hdr  = from->buf_hdr.seg[num + i].hdr;
		to->buf_hdr.seg[i].data = from->buf_hdr.seg[num + i].data;
		to->buf_hdr.seg[i].len  = from->buf_hdr.seg[num + i].len;
	}

	to->buf_hdr.segcount = num;
}

static inline odp_packet_hdr_t *add_segments(odp_packet_hdr_t *pkt_hdr,
					     uint32_t len, int head)
{
	pool_t *pool = pool_entry_from_hdl(pkt_hdr->buf_hdr.pool_hdl);
	odp_packet_hdr_t *new_hdr;
	int num, ret;
	uint32_t seg_len, offset;

	num = num_segments(len);

	if ((pkt_hdr->buf_hdr.segcount + num) > CONFIG_PACKET_MAX_SEGS)
		return NULL;

	{
		odp_buffer_t buf[num];

		ret = buffer_alloc_multi(pool, buf, NULL, num);
		if (odp_unlikely(ret != num)) {
			if (ret > 0)
				buffer_free_multi(buf, ret);

			return NULL;
		}

		new_hdr = init_segments(buf, num);
	}

	seg_len = len - ((num - 1) * pool->max_seg_len);
	offset  = pool->max_seg_len - seg_len;

	if (head) {
		/* add into the head*/
		copy_all_segs(new_hdr, pkt_hdr);

		/* adjust first segment length */
		new_hdr->buf_hdr.seg[0].data += offset;
		new_hdr->buf_hdr.seg[0].len   = seg_len;

		packet_seg_copy_md(new_hdr, pkt_hdr);
		new_hdr->frame_len = pkt_hdr->frame_len + len;
		new_hdr->headroom  = pool->headroom + offset;
		new_hdr->tailroom  = pkt_hdr->tailroom;

		pkt_hdr = new_hdr;
	} else {
		int last;

		/* add into the tail */
		copy_all_segs(pkt_hdr, new_hdr);

		/* adjust last segment length */
		last = packet_last_seg(pkt_hdr);
		pkt_hdr->buf_hdr.seg[last].len = seg_len;

		pkt_hdr->frame_len += len;
		pkt_hdr->tailroom   = pool->tailroom + offset;
	}

	return pkt_hdr;
}

static inline odp_packet_hdr_t *free_segments(odp_packet_hdr_t *pkt_hdr,
					      int num, uint32_t free_len,
					      uint32_t pull_len, int head)
{
	int i;
	odp_buffer_t buf[num];
	int n = pkt_hdr->buf_hdr.segcount - num;

	if (head) {
		odp_packet_hdr_t *new_hdr;

		for (i = 0; i < num; i++)
			buf[i] = buffer_handle(pkt_hdr->buf_hdr.seg[i].hdr);

		/* First remaining segment is the new packet descriptor */
		new_hdr = pkt_hdr->buf_hdr.seg[num].hdr;
		copy_num_segs(new_hdr, pkt_hdr, n);
		packet_seg_copy_md(new_hdr, pkt_hdr);

		/* Tailroom not changed */
		new_hdr->tailroom  = pkt_hdr->tailroom;
		/* No headroom in non-first segments */
		new_hdr->headroom  = 0;
		new_hdr->frame_len = pkt_hdr->frame_len - free_len;

		pull_head(new_hdr, pull_len);

		pkt_hdr = new_hdr;
	} else {
		for (i = 0; i < num; i++)
			buf[i] = buffer_handle(pkt_hdr->buf_hdr.seg[n + i].hdr);

		/* Head segment remains, no need to copy or update majority
		 * of the metadata. */
		pkt_hdr->buf_hdr.segcount = n;
		pkt_hdr->frame_len -= free_len;
		pkt_hdr->tailroom = seg_tailroom(pkt_hdr, n - 1);

		pull_tail(pkt_hdr, pull_len);
	}

	buffer_free_multi(buf, num);

	return pkt_hdr;
}

static inline int packet_alloc(pool_t *pool, uint32_t len, int max_pkt,
			       int num_seg, odp_packet_t *pkt, int parse)
{
	int num_buf, i;
	int num     = max_pkt;
	int max_buf = max_pkt * num_seg;
	odp_buffer_t buf[max_buf];

	num_buf = buffer_alloc_multi(pool, buf, NULL, max_buf);

	/* Failed to allocate all segments */
	if (odp_unlikely(num_buf != max_buf)) {
		int num_free;

		num      = num_buf / num_seg;
		num_free = num_buf - (num * num_seg);

		if (num_free > 0)
			buffer_free_multi(&buf[num_buf - num_free], num_free);

		if (num == 0)
			return 0;
	}

	for (i = 0; i < num; i++) {
		odp_packet_hdr_t *pkt_hdr;

		/* First buffer is the packet descriptor */
		pkt[i]  = (odp_packet_t)buf[i * num_seg];
		pkt_hdr = init_segments(&buf[i * num_seg], num_seg);

		packet_init(pkt_hdr, len, parse);
	}

	return num;
}

int packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
		       odp_packet_t pkt[], int max_num)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);
	int num, num_seg;

	num_seg = num_segments(len);
	num     = packet_alloc(pool, len, max_num, num_seg, pkt, 1);

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

	num_seg = num_segments(len);
	num     = packet_alloc(pool, len, 1, num_seg, &pkt, 0);

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

	num_seg = num_segments(len);
	num     = packet_alloc(pool, len, max_num, num_seg, pkt, 0);

	return num;
}

void odp_packet_free(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	int num_seg = pkt_hdr->buf_hdr.segcount;

	if (odp_likely(CONFIG_PACKET_MAX_SEGS == 1 || num_seg == 1)) {
		buffer_free_multi((odp_buffer_t *)&pkt, 1);
	} else {
		odp_buffer_t buf[num_seg];
		int i;

		buf[0] = (odp_buffer_t)pkt;

		for (i = 1; i < num_seg; i++)
			buf[i] = buffer_handle(pkt_hdr->buf_hdr.seg[i].hdr);

		buffer_free_multi(buf, num_seg);
	}
}

void odp_packet_free_multi(const odp_packet_t pkt[], int num)
{
	if (CONFIG_PACKET_MAX_SEGS == 1) {
		buffer_free_multi((const odp_buffer_t * const)pkt, num);
	} else {
		odp_buffer_t buf[num * CONFIG_PACKET_MAX_SEGS];
		int i, j;
		int bufs = 0;

		for (i = 0; i < num; i++) {
			odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt[i]);
			int num_seg = pkt_hdr->buf_hdr.segcount;
			odp_buffer_hdr_t *buf_hdr = &pkt_hdr->buf_hdr;

			buf[bufs] = (odp_buffer_t)pkt[i];
			bufs++;

			if (odp_likely(num_seg == 1))
				continue;

			for (j = 1; j < num_seg; j++) {
				buf[bufs] = buffer_handle(buf_hdr->seg[j].hdr);
				bufs++;
			}
		}

		buffer_free_multi(buf, bufs);
	}
}

int odp_packet_reset(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);
	pool_t *pool = pool_entry_from_hdl(pkt_hdr->buf_hdr.pool_hdl);

	if (len > pool->headroom + pool->data_size + pool->tailroom)
		return -1;

	packet_init(pkt_hdr, len, 0);

	return 0;
}

odp_packet_t _odp_packet_from_buffer(odp_buffer_t buf)
{
	return (odp_packet_t)buf;
}

odp_buffer_t _odp_packet_to_buffer(odp_packet_t pkt)
{
	return (odp_buffer_t)pkt;
}

odp_packet_t odp_packet_from_event(odp_event_t ev)
{
	return (odp_packet_t)ev;
}

odp_event_t odp_packet_to_event(odp_packet_t pkt)
{
	return (odp_event_t)pkt;
}

/*
 *
 * Pointers and lengths
 * ********************************************************
 *
 */

void *odp_packet_head(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->buf_hdr.seg[0].data - pkt_hdr->headroom;
}

uint32_t odp_packet_buf_len(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->buf_hdr.size * pkt_hdr->buf_hdr.segcount;
}

void *odp_packet_data(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return packet_data(pkt_hdr);
}

uint32_t odp_packet_seg_len(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return packet_first_seg_len(pkt_hdr);
}

uint32_t odp_packet_len(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->frame_len;
}

uint32_t odp_packet_headroom(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->headroom;
}

uint32_t odp_packet_tailroom(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->tailroom;
}

void *odp_packet_tail(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return packet_tail(pkt_hdr);
}

void *odp_packet_push_head(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (len > pkt_hdr->headroom)
		return NULL;

	push_head(pkt_hdr, len);
	return packet_data(pkt_hdr);
}

int odp_packet_extend_head(odp_packet_t *pkt, uint32_t len,
			   void **data_ptr, uint32_t *seg_len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(*pkt);
	odp_packet_hdr_t *new_hdr;
	uint32_t headroom = pkt_hdr->headroom;

	if (len > headroom) {
		push_head(pkt_hdr, headroom);
		new_hdr = add_segments(pkt_hdr, len - headroom, 1);

		if (new_hdr == NULL) {
			/* segment alloc failed, rollback changes */
			pull_head(pkt_hdr, headroom);
			return -1;
		}

		*pkt    = packet_handle(new_hdr);
		pkt_hdr = new_hdr;
	} else {
		push_head(pkt_hdr, len);
	}

	if (data_ptr)
		*data_ptr = packet_data(pkt_hdr);

	if (seg_len)
		*seg_len = packet_first_seg_len(pkt_hdr);

	return 0;
}

void *odp_packet_pull_head(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (len > pkt_hdr->frame_len)
		return NULL;

	pull_head(pkt_hdr, len);
	return packet_data(pkt_hdr);
}

int odp_packet_trunc_head(odp_packet_t *pkt, uint32_t len,
			  void **data_ptr, uint32_t *seg_len_out)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(*pkt);
	uint32_t seg_len = packet_first_seg_len(pkt_hdr);

	if (len > pkt_hdr->frame_len)
		return -1;

	if (len < seg_len) {
		pull_head(pkt_hdr, len);
	} else if (CONFIG_PACKET_MAX_SEGS != 1) {
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
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	void *old_tail;

	if (len > pkt_hdr->tailroom)
		return NULL;

	old_tail = packet_tail(pkt_hdr);
	push_tail(pkt_hdr, len);

	return old_tail;
}

int odp_packet_extend_tail(odp_packet_t *pkt, uint32_t len,
			   void **data_ptr, uint32_t *seg_len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(*pkt);
	void *ret;
	uint32_t tailroom = pkt_hdr->tailroom;
	uint32_t tail_off = pkt_hdr->frame_len;

	if (len > tailroom) {
		push_tail(pkt_hdr, tailroom);
		ret = add_segments(pkt_hdr, len - tailroom, 0);

		if (ret == NULL) {
			/* segment alloc failed, rollback changes */
			pull_tail(pkt_hdr, tailroom);
			return -1;
		}
	} else {
		push_tail(pkt_hdr, len);
	}

	if (data_ptr)
		*data_ptr = packet_map(pkt_hdr, tail_off, seg_len, NULL);

	return 0;
}

void *odp_packet_pull_tail(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (len > packet_last_seg_len(pkt_hdr))
		return NULL;

	pull_tail(pkt_hdr, len);

	return packet_tail(pkt_hdr);
}

int odp_packet_trunc_tail(odp_packet_t *pkt, uint32_t len,
			  void **tail_ptr, uint32_t *tailroom)
{
	int last;
	uint32_t seg_len;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(*pkt);

	if (len > pkt_hdr->frame_len)
		return -1;

	last    = packet_last_seg(pkt_hdr);
	seg_len = packet_seg_len(pkt_hdr, last);

	if (len < seg_len) {
		pull_tail(pkt_hdr, len);
	} else if (CONFIG_PACKET_MAX_SEGS != 1) {
		int num = 0;
		uint32_t pull_len = 0;

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
	int seg_idx;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	void *addr = packet_map(pkt_hdr, offset, len, &seg_idx);

	if (addr != NULL && seg != NULL)
		*seg = seg_idx;

	return addr;
}

/* This function is a no-op */
void odp_packet_prefetch(odp_packet_t pkt ODP_UNUSED,
			 uint32_t offset ODP_UNUSED,
			 uint32_t len ODP_UNUSED)
{
}

/*
 *
 * Meta-data
 * ********************************************************
 *
 */

odp_pool_t odp_packet_pool(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.pool_hdl;
}

odp_pktio_t odp_packet_input(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input;
}

int odp_packet_input_index(odp_packet_t pkt)
{
	return odp_pktio_index(odp_packet_hdr(pkt)->input);
}

void *odp_packet_user_ptr(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.buf_ctx;
}

void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ctx)
{
	odp_packet_hdr(pkt)->buf_hdr.buf_cctx = ctx;
}

void *odp_packet_user_area(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.uarea_addr;
}

uint32_t odp_packet_user_area_size(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.uarea_size;
}

void *odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (!packet_hdr_has_l2(pkt_hdr))
		return NULL;
	return packet_map(pkt_hdr, pkt_hdr->p.l2_offset, len, NULL);
}

uint32_t odp_packet_l2_offset(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (!packet_hdr_has_l2(pkt_hdr))
		return ODP_PACKET_OFFSET_INVALID;
	return pkt_hdr->p.l2_offset;
}

int odp_packet_l2_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (offset >= pkt_hdr->frame_len)
		return -1;

	packet_hdr_has_l2_set(pkt_hdr, 1);
	pkt_hdr->p.l2_offset = offset;
	return 0;
}

void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (pkt_hdr->p.parsed_layers < LAYER_L3)
		packet_parse_layer(pkt_hdr, LAYER_L3);
	return packet_map(pkt_hdr, pkt_hdr->p.l3_offset, len, NULL);
}

uint32_t odp_packet_l3_offset(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (pkt_hdr->p.parsed_layers < LAYER_L3)
		packet_parse_layer(pkt_hdr, LAYER_L3);
	return pkt_hdr->p.l3_offset;
}

int odp_packet_l3_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (offset >= pkt_hdr->frame_len)
		return -1;

	if (pkt_hdr->p.parsed_layers < LAYER_L3)
		packet_parse_layer(pkt_hdr, LAYER_L3);
	pkt_hdr->p.l3_offset = offset;
	return 0;
}

void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (pkt_hdr->p.parsed_layers < LAYER_L4)
		packet_parse_layer(pkt_hdr, LAYER_L4);
	return packet_map(pkt_hdr, pkt_hdr->p.l4_offset, len, NULL);
}

uint32_t odp_packet_l4_offset(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (pkt_hdr->p.parsed_layers < LAYER_L4)
		packet_parse_layer(pkt_hdr, LAYER_L4);
	return pkt_hdr->p.l4_offset;
}

int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (offset >= pkt_hdr->frame_len)
		return -1;

	if (pkt_hdr->p.parsed_layers < LAYER_L4)
		packet_parse_layer(pkt_hdr, LAYER_L4);
	pkt_hdr->p.l4_offset = offset;
	return 0;
}

uint32_t odp_packet_flow_hash(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->flow_hash;
}

void odp_packet_flow_hash_set(odp_packet_t pkt, uint32_t flow_hash)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	pkt_hdr->flow_hash = flow_hash;
	pkt_hdr->p.input_flags.flow_hash = 1;
}

odp_time_t odp_packet_ts(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->timestamp;
}

void odp_packet_ts_set(odp_packet_t pkt, odp_time_t timestamp)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	pkt_hdr->timestamp = timestamp;
	pkt_hdr->p.input_flags.timestamp = 1;
}

int odp_packet_is_segmented(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.segcount > 1;
}

int odp_packet_num_segs(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->buf_hdr.segcount;
}

odp_packet_seg_t odp_packet_first_seg(odp_packet_t pkt)
{
	(void)pkt;

	return 0;
}

odp_packet_seg_t odp_packet_last_seg(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return packet_last_seg(pkt_hdr);
}

odp_packet_seg_t odp_packet_next_seg(odp_packet_t pkt, odp_packet_seg_t seg)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (odp_unlikely(seg >= (odp_packet_seg_t)packet_last_seg(pkt_hdr)))
		return ODP_PACKET_SEG_INVALID;

	return seg + 1;
}

/*
 *
 * Segment level
 * ********************************************************
 *
 */

void *odp_packet_seg_data(odp_packet_t pkt, odp_packet_seg_t seg)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (odp_unlikely(seg >= pkt_hdr->buf_hdr.segcount))
		return NULL;

	return packet_seg_data(pkt_hdr, seg);
}

uint32_t odp_packet_seg_data_len(odp_packet_t pkt, odp_packet_seg_t seg)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (odp_unlikely(seg >= pkt_hdr->buf_hdr.segcount))
		return 0;

	return packet_seg_len(pkt_hdr, seg);
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
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
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
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
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
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(*pkt);
	void *addr = packet_map(pkt_hdr, offset, &seglen, NULL);
	uint64_t uaddr = (uint64_t)(uintptr_t)addr;
	uint64_t misalign;

	if (align > ODP_CACHE_LINE_SIZE)
		return -1;

	if (seglen >= len) {
		misalign = align <= 1 ? 0 :
			ODP_ALIGN_ROUNDUP(uaddr, align) - uaddr;
		if (misalign == 0)
			return 0;
		shift = align - misalign;
	} else {
		if (len > pkt_hdr->buf_hdr.segsize)
			return -1;
		shift  = len - seglen;
		uaddr -= shift;
		misalign = align <= 1 ? 0 :
			ODP_ALIGN_ROUNDUP(uaddr, align) - uaddr;
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
	uint32_t dst_len = odp_packet_len(*dst);
	uint32_t src_len = odp_packet_len(src);

	if (odp_packet_extend_tail(dst, src_len, NULL, NULL) >= 0) {
		(void)odp_packet_copy_from_pkt(*dst, dst_len,
					       src, 0, src_len);
		if (src != *dst)
			odp_packet_free(src);

		return 0;
	}

	return -1;
}

int odp_packet_split(odp_packet_t *pkt, uint32_t len, odp_packet_t *tail)
{
	uint32_t pktlen = odp_packet_len(*pkt);

	if (len >= pktlen || tail == NULL)
		return -1;

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
	odp_packet_hdr_t *srchdr = odp_packet_hdr(pkt);
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

int odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
			   uint32_t len, void *dst)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t cpylen;
	uint8_t *dstaddr = (uint8_t *)dst;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

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
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

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
	odp_packet_hdr_t *dst_hdr = odp_packet_hdr(dst);
	odp_packet_hdr_t *src_hdr = odp_packet_hdr(src);
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

/*
 *
 * Debugging
 * ********************************************************
 *
 */

void odp_packet_print(odp_packet_t pkt)
{
	int max_len = 512;
	char str[max_len];
	int len = 0;
	int n = max_len - 1;
	odp_packet_hdr_t *hdr = odp_packet_hdr(pkt);

	len += snprintf(&str[len], n - len, "Packet ");
	len += odp_buffer_snprint(&str[len], n - len, (odp_buffer_t)pkt);
	len += snprintf(&str[len], n - len, "  input_flags  0x%" PRIx64 "\n",
			hdr->p.input_flags.all);
	len += snprintf(&str[len], n - len, "  error_flags  0x%" PRIx32 "\n",
			hdr->p.error_flags.all);
	len += snprintf(&str[len], n - len,
			"  output_flags 0x%" PRIx32 "\n",
			hdr->p.output_flags.all);
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
	str[len] = '\0';

	ODP_PRINT("\n%s\n", str);
}

int odp_packet_is_valid(odp_packet_t pkt)
{
	if (odp_buffer_is_valid((odp_buffer_t)pkt) == 0)
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
	odp_packet_hdr_t *srchdr = odp_packet_hdr(srcpkt);
	odp_packet_hdr_t *dsthdr = odp_packet_hdr(dstpkt);

	dsthdr->input = srchdr->input;
	dsthdr->dst_queue = srchdr->dst_queue;
	dsthdr->buf_hdr.buf_u64 = srchdr->buf_hdr.buf_u64;
	if (dsthdr->buf_hdr.uarea_addr != NULL &&
	    srchdr->buf_hdr.uarea_addr != NULL)
		memcpy(dsthdr->buf_hdr.uarea_addr,
		       srchdr->buf_hdr.uarea_addr,
		       dsthdr->buf_hdr.uarea_size <=
		       srchdr->buf_hdr.uarea_size ?
		       dsthdr->buf_hdr.uarea_size :
		       srchdr->buf_hdr.uarea_size);

	copy_packet_parser_metadata(srchdr, dsthdr);

	/* Metadata copied, but return indication of whether the packet
	 * user area was truncated in the process. Note this can only
	 * happen when copying between different pools.
	 */
	return dsthdr->buf_hdr.uarea_size < srchdr->buf_hdr.uarea_size;
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

	prs->l3_len = odp_be_to_cpu_16(ipv4->tot_len);

	if (odp_unlikely(ihl < _ODP_IPV4HDR_IHL_MIN) ||
	    odp_unlikely(ver != 4) ||
	    (prs->l3_len > frame_len - *offset)) {
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
	uint32_t dstaddr0 = odp_be_to_cpu_32(ipv6->dst_addr[0]);

	prs->l3_len = odp_be_to_cpu_16(ipv6->payload_len) +
				_ODP_IPV6HDR_LEN;

	/* Basic sanity checks on IPv6 header */
	if ((odp_be_to_cpu_32(ipv6->ver_tc_flow) >> 28) != 6 ||
	    prs->l3_len > frame_len - *offset) {
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

	prs->l4_len = prs->l3_len +
		prs->l3_offset - prs->l4_offset;

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

	if (udplen < sizeof(_odp_udphdr_t) ||
	    udplen > (prs->l3_len +
		      prs->l4_offset - prs->l3_offset)) {
		prs->error_flags.udp_err = 1;
	}

	prs->l4_len = udplen;

	if (offset)
		*offset   += sizeof(_odp_udphdr_t);
	*parseptr += sizeof(_odp_udphdr_t);
}

/**
 * Initialize L2 related parser flags and metadata
 */
void packet_parse_l2(packet_parser_t *prs, uint32_t frame_len)
{
	/* Packet alloc or reset have already init other offsets and flags */

	/* We only support Ethernet for now */
	prs->input_flags.eth = 1;

	/* Detect jumbo frames */
	if (frame_len > _ODP_ETH_LEN_MAX)
		prs->input_flags.jumbo = 1;

	/* Assume valid L2 header, no CRC/FCS check in SW */
	prs->input_flags.l2 = 1;

	prs->input_flags.parsed_l2 = 1;
}

/**
 * Parse common packet headers up to given layer
 *
 * The function expects at least PACKET_PARSE_SEG_LEN bytes of data to be
 * available from the ptr.
 */
int packet_parse_common(packet_parser_t *prs, const uint8_t *ptr,
			uint32_t frame_len, uint32_t seg_len, layer_t layer)
{
	uint32_t offset;
	const uint8_t *parseptr;

	switch (prs->parsed_layers) {
	case LAYER_NONE:
	/* Fall through */

	case LAYER_L2:
	{
		const _odp_ethhdr_t *eth;
		uint16_t macaddr0, macaddr2, macaddr4;
		const _odp_vlanhdr_t *vlan;

		offset = sizeof(_odp_ethhdr_t);
		if (packet_parse_l2_not_done(prs))
			packet_parse_l2(prs, frame_len);

		eth = (const _odp_ethhdr_t *)ptr;

		/* Handle Ethernet broadcast/multicast addresses */
		macaddr0 = odp_be_to_cpu_16(*((const uint16_t *)
					    (const void *)eth));
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
		prs->ethtype = odp_be_to_cpu_16(eth->type);
		parseptr = (const uint8_t *)(eth + 1);

		/* Check for SNAP vs. DIX */
		if (prs->ethtype < _ODP_ETH_LEN_MAX) {
			prs->input_flags.snap = 1;
			if (prs->ethtype > frame_len - offset) {
				prs->error_flags.snap_len = 1;
				goto parse_exit;
			}
			prs->ethtype = odp_be_to_cpu_16(*((const uint16_t *)
							(uintptr_t)
							(parseptr + 6)));
			offset   += 8;
			parseptr += 8;
		}

		/* Parse the VLAN header(s), if present */
		if (prs->ethtype == _ODP_ETHTYPE_VLAN_OUTER) {
			prs->input_flags.vlan_qinq = 1;
			prs->input_flags.vlan = 1;

			vlan = (const _odp_vlanhdr_t *)parseptr;
			prs->ethtype = odp_be_to_cpu_16(vlan->type);
			offset += sizeof(_odp_vlanhdr_t);
			parseptr += sizeof(_odp_vlanhdr_t);
		}

		if (prs->ethtype == _ODP_ETHTYPE_VLAN) {
			prs->input_flags.vlan = 1;
			vlan = (const _odp_vlanhdr_t *)parseptr;
			prs->ethtype = odp_be_to_cpu_16(vlan->type);
			offset += sizeof(_odp_vlanhdr_t);
			parseptr += sizeof(_odp_vlanhdr_t);
		}

		prs->l3_offset = offset;
		prs->parsed_layers = LAYER_L2;
		if (layer == LAYER_L2)
			return prs->error_flags.all != 0;
	}
	/* Fall through */

	case LAYER_L3:
	{
		offset = prs->l3_offset;
		parseptr = (const uint8_t *)(ptr + offset);
		/* Set l3_offset+flag only for known ethtypes */
		prs->input_flags.l3 = 1;

		/* Parse Layer 3 headers */
		switch (prs->ethtype) {
		case _ODP_ETHTYPE_IPV4:
			prs->input_flags.ipv4 = 1;
			prs->ip_proto = parse_ipv4(prs, &parseptr, &offset,
						   frame_len);
			break;

		case _ODP_ETHTYPE_IPV6:
			prs->input_flags.ipv6 = 1;
			prs->ip_proto = parse_ipv6(prs, &parseptr, &offset,
						   frame_len, seg_len);
			break;

		case _ODP_ETHTYPE_ARP:
			prs->input_flags.arp = 1;
			prs->ip_proto = 255;  /* Reserved invalid by IANA */
			break;

		default:
			prs->input_flags.l3 = 0;
			prs->l3_offset = ODP_PACKET_OFFSET_INVALID;
			prs->ip_proto = 255;  /* Reserved invalid by IANA */
		}

		/* Set l4_offset+flag only for known ip_proto */
		prs->l4_offset = offset;
		prs->parsed_layers = LAYER_L3;
		if (layer == LAYER_L3)
			return prs->error_flags.all != 0;
	}
	/* Fall through */

	case LAYER_L4:
	{
		offset = prs->l4_offset;
		parseptr = (const uint8_t *)(ptr + offset);
		prs->input_flags.l4 = 1;

		/* Parse Layer 4 headers */
		switch (prs->ip_proto) {
		case _ODP_IPPROTO_ICMP:
			prs->input_flags.icmp = 1;
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

		prs->parsed_layers = LAYER_L4;
		break;
	}

	case LAYER_ALL:
		break;

	default:
		ODP_ERR("Invalid parse layer: %d\n", (int)layer);
		return -1;
	}

	prs->parsed_layers = LAYER_ALL;

parse_exit:
	return prs->error_flags.all != 0;
}

/**
 * Simple packet parser
 */
int packet_parse_layer(odp_packet_hdr_t *pkt_hdr, layer_t layer)
{
	uint32_t seg_len = packet_first_seg_len(pkt_hdr);
	void *base = packet_data(pkt_hdr);

	return packet_parse_common(&pkt_hdr->p, base, pkt_hdr->frame_len,
				   seg_len, layer);
}
