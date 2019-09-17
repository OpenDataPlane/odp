/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
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
#include <odp/api/debug.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp/api/packet.h>
#include <odp/api/plat/packet_inline_types.h>
#include <odp/api/packet_io.h>
#include <odp/api/crypto.h>
#include <odp/api/comp.h>
#include <odp_ipsec_internal.h>
#include <odp/api/abi/packet.h>
#include <odp_queue_if.h>

#include <stdint.h>

/** Minimum segment length expected by packet_parse_common() */
#define PACKET_PARSE_SEG_LEN 96

ODP_STATIC_ASSERT(sizeof(_odp_packet_input_flags_t) == sizeof(uint64_t),
		  "INPUT_FLAGS_SIZE_ERROR");

ODP_STATIC_ASSERT(sizeof(_odp_packet_flags_t) == sizeof(uint32_t),
		  "PACKET_FLAGS_SIZE_ERROR");

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

/* Packet extra data length */
#define PKT_EXTRA_LEN 128

/* Packet extra data types */
#define PKT_EXTRA_TYPE_DPDK 1

/* Maximum number of segments per packet */
#define PKT_MAX_SEGS 255

ODP_STATIC_ASSERT(PKT_MAX_SEGS < UINT16_MAX, "PACKET_MAX_SEGS_ERROR");

/**
 * Internal Packet header
 *
 * To optimize fast path performance this struct is not initialized to zero in
 * packet_init(). Because of this any new fields added must be reviewed for
 * initialization requirements.
 */
typedef struct odp_packet_hdr_t {
	/* Common buffer header */
	odp_buffer_hdr_t buf_hdr;

	/* --- 64 bytes --- */

	/* Segment data start */
	uint8_t *seg_data;

	packet_parser_t p;

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

	/* Event subtype */
	int8_t   subtype;

	/* --- 128 bytes --- */

	/* Timestamp value */
	odp_time_t timestamp;

	/* Classifier destination queue */
	odp_queue_t dst_queue;

	/* Flow hash value */
	uint32_t flow_hash;

	union {
		struct {
			/* Result for crypto packet op */
			odp_crypto_packet_result_t crypto_op_result;

			/* Context for IPsec */
			odp_ipsec_packet_result_t ipsec_ctx;
		};

		/* Result for comp packet op */
		odp_comp_packet_result_t comp_op_result;
	};

	/* Packet data storage */
	uint8_t data[0];
} odp_packet_hdr_t;

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

static inline odp_buffer_hdr_t *packet_to_buf_hdr(odp_packet_t pkt)
{
	return &packet_hdr(pkt)->buf_hdr;
}

static inline odp_packet_t packet_from_buf_hdr(odp_buffer_hdr_t *buf_hdr)
{
	return (odp_packet_t)(odp_packet_hdr_t *)buf_hdr;
}

static inline odp_packet_hdr_t *packet_last_seg(odp_packet_hdr_t *hdr)
{
	while (hdr->seg_next != NULL)
		hdr = hdr->seg_next;

	return hdr;
}

static inline void packet_subtype_set(odp_packet_t pkt, int ev)
{
	packet_hdr(pkt)->subtype = ev;
}

/**
 * Initialize packet
 */
static inline void packet_init(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	pool_t *pool = pkt_hdr->buf_hdr.pool_ptr;
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

	pkt_hdr->p.input_flags.all  = 0;
	pkt_hdr->p.flags.all_flags  = 0;

	pkt_hdr->p.l2_offset = 0;
	pkt_hdr->p.l3_offset = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->p.l4_offset = ODP_PACKET_OFFSET_INVALID;

       /*
	* Packet headroom is set from the pool's headroom
	* Packet tailroom is rounded up to fill the last
	* segment occupied by the allocated length.
	*/
	pkt_hdr->frame_len = len;
	pkt_hdr->headroom  = CONFIG_PACKET_HEADROOM;
	pkt_hdr->tailroom  = pool->seg_len - seg_len + CONFIG_PACKET_TAILROOM;

	if (odp_unlikely(pkt_hdr->subtype != ODP_EVENT_PACKET_BASIC))
		pkt_hdr->subtype = ODP_EVENT_PACKET_BASIC;

	pkt_hdr->input = ODP_PKTIO_INVALID;
}

static inline void copy_packet_parser_metadata(odp_packet_hdr_t *src_hdr,
					       odp_packet_hdr_t *dst_hdr)
{
	dst_hdr->p = src_hdr->p;
}

static inline void copy_packet_cls_metadata(odp_packet_hdr_t *src_hdr,
					    odp_packet_hdr_t *dst_hdr)
{
	dst_hdr->p = src_hdr->p;
	dst_hdr->dst_queue = src_hdr->dst_queue;
	dst_hdr->flow_hash = src_hdr->flow_hash;
	dst_hdr->timestamp = src_hdr->timestamp;
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

/* Forward declarations */
int _odp_packet_copy_md_to_packet(odp_packet_t srcpkt, odp_packet_t dstpkt);

/* Packet alloc of pktios */
int packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
		       odp_packet_t pkt[], int max_num);

/* Perform packet parse up to a given protocol layer */
int packet_parse_layer(odp_packet_hdr_t *pkt_hdr,
		       odp_proto_layer_t layer,
		       odp_proto_chksums_t chksums);

/* Reset parser metadata for a new parse */
void packet_parse_reset(odp_packet_hdr_t *pkt_hdr);

static inline int packet_hdr_has_l2(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->p.input_flags.l2;
}

static inline void packet_hdr_has_l2_set(odp_packet_hdr_t *pkt_hdr, int val)
{
	pkt_hdr->p.input_flags.l2 = val;
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

int packet_parse_common(packet_parser_t *pkt_hdr, const uint8_t *ptr,
			uint32_t pkt_len, uint32_t seg_len, int layer,
			odp_proto_chksums_t chksums);

int _odp_cls_parse(odp_packet_hdr_t *pkt_hdr, const uint8_t *parseptr);

int _odp_packet_set_data(odp_packet_t pkt, uint32_t offset,
			 uint8_t c, uint32_t len);

int _odp_packet_cmp_data(odp_packet_t pkt, uint32_t offset,
			 const void *s, uint32_t len);

int _odp_packet_ipv4_chksum_insert(odp_packet_t pkt);
int _odp_packet_tcp_chksum_insert(odp_packet_t pkt);
int _odp_packet_udp_chksum_insert(odp_packet_t pkt);
int _odp_packet_sctp_chksum_insert(odp_packet_t pkt);

#ifdef __cplusplus
}
#endif

#endif
