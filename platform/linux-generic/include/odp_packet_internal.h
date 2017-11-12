/* Copyright (c) 2013, Linaro Limited
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
#include <odp_buffer_inlines.h>
#include <odp/api/packet.h>
#include <odp/api/packet_io.h>
#include <odp/api/crypto.h>
#include <odp_ipsec_internal.h>
#include <odp/api/plat/packet_types.h>
#include <odp_queue_if.h>

/** Minimum segment length expected by packet_parse_common() */
#define PACKET_PARSE_SEG_LEN 96


ODP_STATIC_ASSERT(sizeof(_odp_packet_input_flags_t) == sizeof(uint64_t),
		  "INPUT_FLAGS_SIZE_ERROR");

/**
 * Packet error flags
 */
typedef union {
	/* All error flags */
	uint32_t all;

	struct {
		/* Bitfield flags for each detected error */
		uint32_t app_error:1; /**< Error bit for application use */
		uint32_t frame_len:1; /**< Frame length error */
		uint32_t snap_len:1;  /**< Snap length error */
		uint32_t l2_chksum:1; /**< L2 checksum error, checks TBD */
		uint32_t ip_err:1;    /**< IP error,  checks TBD */
		uint32_t tcp_err:1;   /**< TCP error, checks TBD */
		uint32_t udp_err:1;   /**< UDP error, checks TBD */
		uint32_t ipsec_err:1; /**< IPsec error */
		uint32_t crypto_err:1; /**< Crypto packet operation error */
	};
} error_flags_t;

ODP_STATIC_ASSERT(sizeof(error_flags_t) == sizeof(uint32_t),
		  "ERROR_FLAGS_SIZE_ERROR");

/**
 * Packet output flags
 */
typedef union {
	/* All output flags */
	uint32_t all;

	struct {
		/** adjustment for traffic mgr */
		uint32_t shaper_len_adj:8;

		/* Bitfield flags for each output option */
		uint32_t l3_chksum_set:1; /**< L3 chksum bit is valid */
		uint32_t l3_chksum:1;     /**< L3 chksum override */
		uint32_t l4_chksum_set:1; /**< L3 chksum bit is valid */
		uint32_t l4_chksum:1;     /**< L4 chksum override  */
	};
} output_flags_t;

ODP_STATIC_ASSERT(sizeof(output_flags_t) == sizeof(uint32_t),
		  "OUTPUT_FLAGS_SIZE_ERROR");

/**
 * Packet parser metadata
 */
typedef struct {
	_odp_packet_input_flags_t  input_flags;
	error_flags_t  error_flags;
	output_flags_t output_flags;

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

/**
 * Internal Packet header
 *
 * To optimize fast path performance this struct is not initialized to zero in
 * packet_init(). Because of this any new fields added must be reviewed for
 * initialization requirements.
 */
typedef struct {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;

	/*
	 * Following members are initialized by packet_init()
	 */

	packet_parser_t p;

	odp_pktio_t input;

	uint32_t frame_len;

	uint16_t headroom;
	uint16_t tailroom;

	/*
	 * Members below are not initialized by packet_init()
	 */

	/* Flow hash value */
	uint32_t flow_hash;

	/* Timestamp value */
	odp_time_t timestamp;

	/* Classifier destination queue */
	queue_t dst_queue;

	/* Result for crypto packet op */
	odp_crypto_packet_result_t crypto_op_result;

#ifdef ODP_PKTIO_DPDK
	/* Type of extra data */
	uint8_t extra_type;
	/* Extra space for packet descriptors. E.g. DPDK mbuf  */
	uint8_t extra[PKT_EXTRA_LEN] ODP_ALIGNED_CACHE;
#endif

	/* Context for IPsec */
	odp_ipsec_packet_result_t ipsec_ctx;

	/* Packet data storage */
	uint8_t data[0];
} odp_packet_hdr_t;

/**
 * Return the packet header
 */
static inline odp_packet_hdr_t *odp_packet_hdr(odp_packet_t pkt)
{
	return (odp_packet_hdr_t *)(uintptr_t)pkt;
}

static inline odp_packet_t packet_handle(odp_packet_hdr_t *pkt_hdr)
{
	return (odp_packet_t)pkt_hdr;
}

static inline odp_buffer_hdr_t *packet_to_buf_hdr(odp_packet_t pkt)
{
	return &odp_packet_hdr(pkt)->buf_hdr;
}

static inline odp_packet_t packet_from_buf_hdr(odp_buffer_hdr_t *buf_hdr)
{
	return (odp_packet_t)(odp_packet_hdr_t *)buf_hdr;
}

static inline seg_entry_t *seg_entry_last(odp_packet_hdr_t *hdr)
{
	odp_packet_hdr_t *last;
	uint8_t last_seg;

	last     = hdr->buf_hdr.last_seg;
	last_seg = last->buf_hdr.num_seg - 1;
	return &last->buf_hdr.seg[last_seg];
}

/**
 * Initialize packet
 */
static inline void packet_init(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	pool_t *pool = pkt_hdr->buf_hdr.pool_ptr;
	uint32_t seg_len;
	int num = pkt_hdr->buf_hdr.segcount;

	if (odp_likely(CONFIG_PACKET_SEG_DISABLED || num == 1)) {
		seg_len = len;
		pkt_hdr->buf_hdr.seg[0].len = len;
	} else {
		seg_entry_t *last;

		seg_len = len - ((num - 1) * pool->seg_len);

		/* Last segment data length */
		last      = seg_entry_last(pkt_hdr);
		last->len = seg_len;
	}

	pkt_hdr->p.input_flags.all  = 0;
	pkt_hdr->p.output_flags.all = 0;
	pkt_hdr->p.error_flags.all  = 0;

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

	pkt_hdr->input = ODP_PKTIO_INVALID;
	pkt_hdr->buf_hdr.event_subtype = ODP_EVENT_PACKET_BASIC;
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
	seg_entry_t *last = seg_entry_last(pkt_hdr);

	pkt_hdr->tailroom  += len;
	pkt_hdr->frame_len -= len;
	last->len          -= len;
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
		       odp_pktio_parser_layer_t layer);

/* Perform L3 and L4 parsing up to a given protocol layer */
int packet_parse_l3_l4(odp_packet_hdr_t *pkt_hdr,
		       odp_pktio_parser_layer_t layer,
		       uint32_t l3_offset,
		       uint16_t ethtype);

/* Reset parser metadata for a new parse */
void packet_parse_reset(odp_packet_hdr_t *pkt_hdr);

/* Convert a buffer handle to a packet handle */
odp_packet_t _odp_packet_from_buf_hdr(odp_buffer_hdr_t *buf_hdr);

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

static inline void packet_set_ts(odp_packet_hdr_t *pkt_hdr, odp_time_t *ts)
{
	if (ts != NULL) {
		pkt_hdr->timestamp = *ts;
		pkt_hdr->p.input_flags.timestamp = 1;
	}
}

int packet_parse_common(packet_parser_t *pkt_hdr, const uint8_t *ptr,
			uint32_t pkt_len, uint32_t seg_len, int layer);

int _odp_cls_parse(odp_packet_hdr_t *pkt_hdr, const uint8_t *parseptr);

int _odp_packet_set_data(odp_packet_t pkt, uint32_t offset,
			 uint8_t c, uint32_t len);

int _odp_packet_cmp_data(odp_packet_t pkt, uint32_t offset,
			 const void *s, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
