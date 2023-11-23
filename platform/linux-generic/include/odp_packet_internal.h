/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet descriptor - implementation internal
 */

#ifndef ODP_PACKET_INTERNAL_H_
#define ODP_PACKET_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/atomic.h>
#include <odp/api/debug.h>
#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/packet_io.h>
#include <odp/api/crypto.h>
#include <odp/api/comp.h>
#include <odp/api/std.h>

#include <odp/api/plat/packet_inline_types.h>

#include <odp_debug_internal.h>
#include <odp_event_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_pool_internal.h>
#include <odp_queue_if.h>
#include <odp_config_internal.h>

#include <stdint.h>
#include <string.h>

ODP_STATIC_ASSERT(sizeof(_odp_packet_input_flags_t) == sizeof(uint64_t),
		  "INPUT_FLAGS_SIZE_ERROR");

ODP_STATIC_ASSERT(sizeof(_odp_packet_flags_t) == sizeof(uint32_t),
		  "PACKET_FLAGS_SIZE_ERROR");

/* Maximum number of segments per packet */
#define PKT_MAX_SEGS 255

ODP_STATIC_ASSERT(PKT_MAX_SEGS < UINT16_MAX, "PACKET_MAX_SEGS_ERROR");

/**
 * Packet parser metadata
 */
typedef struct {
	/* Packet input flags */
	_odp_packet_input_flags_t  input_flags;

	/* Other flags */
	_odp_packet_flags_t        flags;

	 /* offset to L2 hdr, e.g. Eth */
	uint16_t l2_offset;

	/* offset to L3 hdr, e.g. IPv4, IPv6 */
	uint16_t l3_offset;

	/* offset to L4 hdr (TCP, UDP, SCTP, also ICMP) */
	uint16_t l4_offset;
} packet_parser_t;

/**
 * Internal Packet header
 *
 * To optimize fast path performance this struct is not initialized to zero in
 * packet_init(). Because of this any new fields added must be reviewed for
 * initialization requirements.
 */
typedef struct ODP_ALIGNED_CACHE odp_packet_hdr_t {
	/* Common event header */
	_odp_event_hdr_t event_hdr;

	/* Segment data start */
	uint8_t *seg_data;

	packet_parser_t p;

	/* --- 64-byte cache line boundary --- */

	odp_pktio_t input;

	/* Next header which continues the segment list */
	struct odp_packet_hdr_t *seg_next;

	/* Total packet length */
	uint32_t frame_len;

	/* Segment data length */
	uint32_t seg_len;

	/* Total segment count */
	uint16_t seg_count;

	uint16_t headroom;

	uint16_t tailroom;

	/* Used as classifier destination queue, in IPsec inline input processing and as Tx
	 * completion event queue. */
	odp_queue_t dst_queue;

	/* Reference count */
	odp_atomic_u32_t ref_cnt;

	/* Flow hash value */
	uint32_t flow_hash;

	/* User area pointer */
	void *uarea_addr;

	/* User context pointer */
	const void *user_ptr;

	/* --- 64-byte cache line boundary --- */

	/* Timestamp value */
	odp_time_t timestamp;

	/* Classifier mark */
	uint16_t cls_mark;

	/* Classifier handle index */
	uint16_t cos;

	/* Offset to payload start */
	uint16_t payload_offset;

	/* Max payload size in a LSO segment */
	uint16_t lso_max_payload;

	/* Packet aging drop timeout before enqueue. Once enqueued holds the maximum age (time of
	 * request + requested drop timeout). */
	uint64_t tx_aging_ns;

	/* Tx completion poll completion identifier */
	uint32_t tx_compl_id;

	/* LSO profile index */
	uint8_t lso_profile_idx;

	/* Pktio where packet is used as a memory source */
	uint8_t ms_pktio_idx;

	union {
		/* Result for crypto packet op */
		odp_crypto_packet_result_t crypto_op_result;

		/* Context for IPsec */
		odp_ipsec_packet_result_t ipsec_ctx;

		/* Result for comp packet op */
		odp_comp_packet_result_t comp_op_result;
	};

	/* Packet data storage */
	uint8_t data[];

} odp_packet_hdr_t;

/* Packet header size is critical for performance. Ensure that it does not accidentally
 * grow over 256 bytes. */
ODP_STATIC_ASSERT(sizeof(odp_packet_hdr_t) <= 256, "PACKET_HDR_SIZE_ERROR");

ODP_STATIC_ASSERT(CONFIG_PKTIO_ENTRIES < UINT8_MAX, "MS_PKTIO_IDX_SIZE_ERROR");

/**
 * Return the packet header
 */
static inline odp_packet_hdr_t *packet_hdr(odp_packet_t pkt)
{
	return (odp_packet_hdr_t *)(uintptr_t)pkt;
}

static inline odp_packet_t packet_handle(odp_packet_hdr_t *pkt_hdr)
{
	return (odp_packet_t)pkt_hdr;
}

static inline _odp_event_hdr_t *packet_to_event_hdr(odp_packet_t pkt)
{
	return (_odp_event_hdr_t *)(uintptr_t)&packet_hdr(pkt)->event_hdr;
}

static inline odp_packet_t packet_from_event_hdr(_odp_event_hdr_t *event_hdr)
{
	return (odp_packet_t)(uintptr_t)event_hdr;
}

static inline uint32_t packet_first_seg_len(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->seg_len;
}

static inline odp_packet_hdr_t *packet_last_seg(odp_packet_hdr_t *hdr)
{
	while (hdr->seg_next != NULL)
		hdr = hdr->seg_next;

	return hdr;
}

static inline void packet_subtype_set(odp_packet_t pkt, int subtype)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->event_hdr.subtype = subtype;
}

/**
 * Initialize packet
 */
static inline void packet_init(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	pool_t *pool = _odp_pool_entry(pkt_hdr->event_hdr.pool);
	uint32_t seg_len;
	int num = pkt_hdr->seg_count;

	if (odp_likely(num == 1)) {
		seg_len = len;
		pkt_hdr->seg_len = len;
	} else {
		odp_packet_hdr_t *last;

		seg_len = len - ((num - 1) * pool->seg_len);

		/* Last segment data length */
		last = packet_last_seg(pkt_hdr);
		last->seg_len = seg_len;
	}

	/* Clear all flags. Resets also return value of cls_mark, user_ptr, etc. */
	pkt_hdr->p.input_flags.all = 0;
	pkt_hdr->p.flags.all_flags = 0;

	pkt_hdr->p.l2_offset = 0;
	pkt_hdr->p.l3_offset = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->p.l4_offset = ODP_PACKET_OFFSET_INVALID;

       /*
	* Packet headroom is set from the pool's headroom
	* Packet tailroom is rounded up to fill the last
	* segment occupied by the allocated length.
	*/
	pkt_hdr->frame_len = len;
	pkt_hdr->headroom  = pool->headroom;
	pkt_hdr->tailroom  = pool->seg_len - seg_len + pool->tailroom;

	if (odp_unlikely(pkt_hdr->event_hdr.subtype != ODP_EVENT_PACKET_BASIC))
		pkt_hdr->event_hdr.subtype = ODP_EVENT_PACKET_BASIC;

	pkt_hdr->input = ODP_PKTIO_INVALID;
}

/**
 * Check if copying packet metadata between pools is possible
 *
 * @retval  0 when possible without user area copy
 * @retval >0 when possible with user area copy
 * @retval <0 when not possible
 */
static inline int _odp_packet_copy_md_possible(odp_pool_t dst_pool,
					       odp_pool_t src_pool)
{
	const pool_t *src_hdr;
	const pool_t *dst_hdr;

	if (src_pool == dst_pool)
		return 0;

	src_hdr = _odp_pool_entry(src_pool);
	dst_hdr = _odp_pool_entry(dst_pool);

	if (dst_hdr->param_uarea_size < src_hdr->param_uarea_size)
		return -1;

	return 1;
}

/**
 * Copy packet metadata
 *
 * This function is assumed to never fail. Use _odp_packet_copy_md_possible() to
 * check beforehand that copying packet metadata between source and destination
 * packet pools is possible.
 *
 * @param      uarea_copy  Copy user area data. If false, user area pointers
 *                         are swapped between the packet headers (allowed
 *                         only when packets are from the same pool).
 */
static inline void _odp_packet_copy_md(odp_packet_hdr_t *dst_hdr,
				       odp_packet_hdr_t *src_hdr,
				       odp_bool_t uarea_copy)
{
	int8_t subtype = src_hdr->event_hdr.subtype;

	/* Lengths and segmentation data are not copied:
	 *   .frame_len
	 *   .headroom
	 *   .tailroom
	 *   .seg_data
	 *   .seg_next
	 *   .seg_len
	 *   .seg_count
	 */
	dst_hdr->input = src_hdr->input;
	dst_hdr->event_hdr.subtype = subtype;
	dst_hdr->dst_queue = src_hdr->dst_queue;
	dst_hdr->cos = src_hdr->cos;
	dst_hdr->cls_mark = src_hdr->cls_mark;
	dst_hdr->user_ptr = src_hdr->user_ptr;

	if (src_hdr->p.input_flags.flow_hash)
		dst_hdr->flow_hash = src_hdr->flow_hash;

	if (src_hdr->p.input_flags.timestamp)
		dst_hdr->timestamp = src_hdr->timestamp;

	if (src_hdr->p.flags.lso) {
		dst_hdr->lso_max_payload = src_hdr->lso_max_payload;
		dst_hdr->lso_profile_idx = src_hdr->lso_profile_idx;
	}

	if (src_hdr->p.flags.payload_off)
		dst_hdr->payload_offset = src_hdr->payload_offset;

	dst_hdr->p = src_hdr->p;

	if (src_hdr->uarea_addr) {
		if (uarea_copy) {
			const pool_t *src_pool = _odp_pool_entry(src_hdr->event_hdr.pool);
			const pool_t *dst_pool = _odp_pool_entry(dst_hdr->event_hdr.pool);
			const uint32_t src_uarea_size = src_pool->param_uarea_size;
			const uint32_t dst_uarea_size = dst_pool->param_uarea_size;

			_ODP_ASSERT(dst_hdr->uarea_addr != NULL);
			_ODP_ASSERT(dst_uarea_size >= src_uarea_size);

			memcpy(dst_hdr->uarea_addr, src_hdr->uarea_addr, src_uarea_size);
		} else {
			void *src_uarea = src_hdr->uarea_addr;

			/* If user area exists, packets should always be from the same pool, so
			 * user area pointers can simply be swapped. */
			_ODP_ASSERT(dst_hdr->event_hdr.pool == src_hdr->event_hdr.pool);

			src_hdr->uarea_addr = dst_hdr->uarea_addr;
			dst_hdr->uarea_addr = src_uarea;
		}
	}

	if (odp_unlikely(subtype != ODP_EVENT_PACKET_BASIC)) {
		if (subtype == ODP_EVENT_PACKET_IPSEC)
			dst_hdr->ipsec_ctx = src_hdr->ipsec_ctx;
		else if (subtype == ODP_EVENT_PACKET_CRYPTO)
			dst_hdr->crypto_op_result = src_hdr->crypto_op_result;
		else if (subtype == ODP_EVENT_PACKET_COMP)
			dst_hdr->comp_op_result = src_hdr->comp_op_result;
	}
}

static inline void _odp_packet_copy_cls_md(odp_packet_hdr_t *dst_hdr,
					   odp_packet_hdr_t *src_hdr)
{
	dst_hdr->p = src_hdr->p;
	dst_hdr->dst_queue = src_hdr->dst_queue;
	dst_hdr->cos = src_hdr->cos;
	dst_hdr->cls_mark  = src_hdr->cls_mark;
}

static inline void *packet_data(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->seg_data;
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
	pkt_hdr->seg_data  += len;
	pkt_hdr->seg_len   -= len;
}

static inline void pull_tail(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	odp_packet_hdr_t *last = packet_last_seg(pkt_hdr);

	pkt_hdr->tailroom  += len;
	pkt_hdr->frame_len -= len;
	last->seg_len      -= len;
}

static inline uint32_t packet_len(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->frame_len;
}

static inline void packet_set_len(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	pkt_hdr->frame_len = len;
}

/* Packet alloc of pktios */
int _odp_packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
			    odp_packet_t pkt[], int max_num);

/* Reset parser metadata for a new parse */
static inline void packet_parse_reset(odp_packet_hdr_t *pkt_hdr, int all)
{
	pkt_hdr->p.input_flags.all  = 0;
	pkt_hdr->p.l2_offset        = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->p.l3_offset        = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->p.l4_offset        = ODP_PACKET_OFFSET_INVALID;

	if (all)
		pkt_hdr->p.flags.all_flags = 0;
	else /* Keep user ptr and pktout flags */
		pkt_hdr->p.flags.all.error = 0;
}

static inline int packet_hdr_has_l2(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->p.input_flags.l2;
}

static inline int packet_hdr_has_eth(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->p.input_flags.eth;
}

static inline int packet_hdr_has_ipv6(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->p.input_flags.ipv6;
}

static inline void packet_set_flow_hash(odp_packet_hdr_t *pkt_hdr,
					uint32_t flow_hash)
{
	pkt_hdr->flow_hash = flow_hash;
	pkt_hdr->p.input_flags.flow_hash = 1;
}

static inline void packet_set_ts(odp_packet_hdr_t *pkt_hdr, odp_time_t *ts)
{
	if (ts != NULL) {
		pkt_hdr->timestamp = *ts;
		pkt_hdr->p.input_flags.timestamp = 1;
	}
}

int _odp_packet_set_data(odp_packet_t pkt, uint32_t offset,
			 uint8_t c, uint32_t len);

int _odp_packet_cmp_data(odp_packet_t pkt, uint32_t offset,
			 const void *s, uint32_t len);

int _odp_packet_ipv4_chksum_insert(odp_packet_t pkt);
int _odp_packet_tcp_chksum_insert(odp_packet_t pkt);
int _odp_packet_udp_chksum_insert(odp_packet_t pkt);
int _odp_packet_sctp_chksum_insert(odp_packet_t pkt);

int _odp_packet_l4_chksum(odp_packet_hdr_t *pkt_hdr,
			  odp_pktin_config_opt_t opt, uint64_t l4_part_sum);

#ifdef __cplusplus
}
#endif

#endif
