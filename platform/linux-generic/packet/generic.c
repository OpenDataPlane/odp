/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <odp/api/plat/packet_inlines.h>
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

/* Initial packet segment data length */
#define BASE_LEN  CONFIG_PACKET_MAX_SEG_LEN

static inline odp_packet_hdr_t *packet_hdr(odp_packet_t pkt)
{
	return (odp_packet_hdr_t *)(uintptr_t)pkt;
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

static inline void init_segments(odp_packet_hdr_t *pkt_hdr[], int num)
{
	odp_packet_hdr_t *hdr;
	int i;

	/* First segment is the packet descriptor */
	hdr = pkt_hdr[0];

	hdr->buf_hdr.seg[0].data = hdr->buf_hdr.base_data;
	hdr->buf_hdr.seg[0].len  = BASE_LEN;
	packet_ref_count_set(hdr, 1);

	/* Link segments */
	if (CONFIG_PACKET_MAX_SEGS != 1) {
		hdr->buf_hdr.segcount = num;

		if (odp_unlikely(num > 1)) {
			for (i = 1; i < num; i++) {
				odp_buffer_hdr_t *buf_hdr;

				packet_ref_count_set(pkt_hdr[i], 1);
				buf_hdr = &pkt_hdr[i]->buf_hdr;
				hdr->buf_hdr.seg[i].hdr  = buf_hdr;
				hdr->buf_hdr.seg[i].data = buf_hdr->base_data;
				hdr->buf_hdr.seg[i].len  = BASE_LEN;
			}
		}
	}
}

static inline int packet_alloc(pool_t *pool, uint32_t len, int max_pkt,
			       int num_seg, odp_packet_t *pkt)
{
	int num_buf, i;
	int num     = max_pkt;
	int max_buf = max_pkt * num_seg;
	odp_packet_hdr_t *pkt_hdr[max_buf];

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

	for (i = 0; i < num; i++) {
		odp_packet_hdr_t *hdr;

		/* First buffer is the packet descriptor */
		hdr    = pkt_hdr[i * num_seg];
		pkt[i] = packet_handle(hdr);
		init_segments(&pkt_hdr[i * num_seg], num_seg);

		packet_init(hdr, len);
	}

	return num;
}

int packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
		       odp_packet_t pkt[], int max_num)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);
	int num, num_seg;

	num_seg = num_segments(len);
	num     = packet_alloc(pool, len, max_num, num_seg, pkt);

	return num;
}

static inline uint32_t packet_ref_dec(odp_packet_hdr_t *pkt_hdr)
{
	return odp_atomic_fetch_dec_u32(&pkt_hdr->ref_count);
}

static inline void free_bufs(odp_packet_hdr_t *pkt_hdr, int first, int num)
{
	int i, nfree;
	odp_buffer_hdr_t *buf_hdr[num];

	for (i = 0, nfree = 0; i < num; i++) {
		odp_packet_hdr_t *hdr = pkt_hdr->buf_hdr.seg[first + i].hdr;

		if (packet_ref_count(hdr) == 1 || packet_ref_dec(hdr) == 1) {
			ODP_ASSERT((packet_ref_count_set(hdr, 0), 1));
			buf_hdr[nfree++] = &hdr->buf_hdr;
		}
	}

	if (nfree > 0)
		buffer_free_multi(buf_hdr, nfree);
}

static odp_packet_t generic_packet_alloc(odp_pool_t pool_hdl, uint32_t len)
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
	num     = packet_alloc(pool, len, 1, num_seg, &pkt);

	if (odp_unlikely(num == 0))
		return ODP_PACKET_INVALID;

	return pkt;
}

static int generic_packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
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
	num     = packet_alloc(pool, len, max_num, num_seg, pkt);

	return num;
}

static void generic_packet_free(odp_packet_t pkt)
{
	odp_packet_hdr_t *ref_hdr, *pkt_hdr;
	odp_buffer_hdr_t *buf_hdr;
	uint32_t ref_count;
	int num_seg;

	pkt_hdr = packet_hdr(pkt);
	do {
		buf_hdr = &pkt_hdr->buf_hdr;
		ref_count = packet_ref_count(pkt_hdr);
		num_seg = pkt_hdr->buf_hdr.segcount;
		ref_hdr = pkt_hdr->ref_hdr;
		ODP_ASSERT(ref_count >= 1);

		if (odp_likely((CONFIG_PACKET_MAX_SEGS == 1 || num_seg == 1) &&
			       ref_count == 1)) {
			ODP_ASSERT((packet_ref_count_set(pkt_hdr, 0), 1));
			buffer_free_multi(&buf_hdr, 1);
		} else {
			free_bufs(pkt_hdr, 0, num_seg);
		}

		pkt_hdr = ref_hdr;
	} while (pkt_hdr);
}

static void generic_packet_free_multi(const odp_packet_t pkt[], int num)
{
	odp_packet_hdr_t *pkt_hdr, *ref_hdr, *hdr;
	int nbufs = num * CONFIG_PACKET_MAX_SEGS * 2;
	odp_buffer_hdr_t *buf_hdr[nbufs];
	int num_seg;
	int i, j;
	uint32_t ref_count;
	int nfree = 0;

	for (i = 0; i < num; i++) {
		pkt_hdr = packet_hdr(pkt[i]);

		do {
			num_seg = pkt_hdr->buf_hdr.segcount;
			ref_hdr = pkt_hdr->ref_hdr;

			/* Make sure we have enough space for this pkt's segs */
			if (nfree + num_seg > nbufs) {
				buffer_free_multi(buf_hdr, nfree);
				nfree = 0;
			}

			for (j = 0; j < num_seg; j++) {
				hdr = pkt_hdr->buf_hdr.seg[j].hdr;
				ref_count = packet_ref_count(hdr);
				ODP_ASSERT(ref_count >= 1);

				if (ref_count == 1 ||
				    packet_ref_dec(hdr) == 1) {
					ODP_ASSERT
						((packet_ref_count_set(hdr, 0),
						  1));
					buf_hdr[nfree++] = &hdr->buf_hdr;
				}
			}

			pkt_hdr = ref_hdr;
		} while (pkt_hdr);
	}

	if (nfree > 0)
		buffer_free_multi(buf_hdr, nfree);
}

static int generic_packet_has_error(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->p.error_flags.all != 0;
}

static void generic_packet_prefetch(odp_packet_t pkt, uint32_t offset,
				    uint32_t len)
{
	return _odp_packet_prefetch(pkt, offset, len);
}

static void *generic_packet_data(odp_packet_t pkt)
{
	return _odp_packet_data(pkt);
}

static int generic_packet_input_index(odp_packet_t pkt)
{
	return odp_pktio_index(packet_hdr(pkt)->input);
}

odp_packet_module_t generic_packet = {
	.base = {
		.name = "generic_packet",
		.init_local = NULL,
		.term_local = NULL,
		.init_global = NULL,
		.term_global = NULL,
		},
	.packet_alloc = generic_packet_alloc,
	.packet_alloc_multi = generic_packet_alloc_multi,
	.packet_free = generic_packet_free,
	.packet_free_multi = generic_packet_free_multi,
	.packet_has_error = generic_packet_has_error,
	.packet_prefetch = generic_packet_prefetch,
	.packet_data = generic_packet_data,
	.packet_input_index = generic_packet_input_index,
};

ODP_MODULE_CONSTRUCTOR(generic_packet)
{
	odp_module_constructor(&generic_packet);
	odp_subsystem_register_module(packet, &generic_packet);
}

