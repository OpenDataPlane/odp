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
#include <odp_debug_internal.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp/api/packet.h>
#include <odp/api/packet_io.h>
#include <odp/api/crypto.h>
#include <odp_crypto_internal.h>
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

	uint32_t l2_offset; /**< offset to L2 hdr, e.g. Eth */
	uint32_t l3_offset; /**< offset to L3 hdr, e.g. IPv4, IPv6 */
	uint32_t l4_offset; /**< offset to L4 hdr (TCP, UDP, SCTP, also ICMP) */
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
typedef struct odp_packet_hdr_t {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;

	/*
	 * Following members are initialized by packet_init()
	 */

	packet_parser_t p;

	odp_pktio_t input;

	uint32_t frame_len;
	uint32_t headroom;
	uint32_t tailroom;

	/* Fields used to support packet references */
	uint32_t unshared_len;
	/* Next pkt_hdr in reference chain */
	struct odp_packet_hdr_t *ref_hdr;
	/* Offset into next pkt_hdr that ref was created at */
	uint32_t ref_offset;
	/* frame_len in next pkt_hdr at time ref was created. This
	 * allows original offset to be maintained when base pkt len
	 * is changed */
	uint32_t ref_len;
	/* Incremented on refs, decremented on frees. */
	odp_atomic_u32_t ref_count;

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

static inline odp_packet_hdr_t *packet_last_hdr(odp_packet_t pkt,
						uint32_t *offset)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	odp_packet_hdr_t *prev_hdr = pkt_hdr;
	uint32_t ref_offset = 0;

	while (pkt_hdr->ref_hdr) {
		ref_offset = pkt_hdr->ref_offset;
		prev_hdr   = pkt_hdr;
		pkt_hdr    = pkt_hdr->ref_hdr;
	}

	if (offset) {
		if (prev_hdr != pkt_hdr)
			ref_offset += pkt_hdr->frame_len - prev_hdr->ref_len;
		*offset = ref_offset;
	}

	return pkt_hdr;
}

static inline odp_packet_hdr_t *packet_prev_hdr(odp_packet_hdr_t *pkt_hdr,
						odp_packet_hdr_t *cur_hdr,
						uint32_t *offset)
{
	uint32_t ref_offset = 0;
	odp_packet_hdr_t *prev_hdr = pkt_hdr;

	while (pkt_hdr->ref_hdr != cur_hdr) {
		ref_offset = pkt_hdr->ref_offset;
		prev_hdr   = pkt_hdr;
		pkt_hdr    = pkt_hdr->ref_hdr;
	}

	if (offset) {
		if (prev_hdr != pkt_hdr)
			ref_offset += pkt_hdr->frame_len - prev_hdr->ref_len;
		*offset = ref_offset;
	}

	return pkt_hdr;
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

static inline odp_buffer_t packet_to_buffer(odp_packet_t pkt)
{
	return (odp_buffer_t)pkt;
}

/**
 * Initialize packet
 */
static inline void packet_init(odp_packet_hdr_t *pkt_hdr, uint32_t len)
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
	pkt_hdr->tailroom  = CONFIG_PACKET_MAX_SEG_LEN - seg_len +
			     CONFIG_PACKET_TAILROOM;

	pkt_hdr->input = ODP_PKTIO_INVALID;
	pkt_hdr->buf_hdr.event_subtype = ODP_EVENT_PACKET_BASIC;

	/* By default packet has no references */
	pkt_hdr->unshared_len = len;
	pkt_hdr->ref_hdr = NULL;
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
	int last = pkt_hdr->buf_hdr.segcount - 1;

	pkt_hdr->tailroom  += len;
	pkt_hdr->frame_len -= len;
	pkt_hdr->unshared_len -= len;
	pkt_hdr->buf_hdr.seg[last].len -= len;
}

static inline uint32_t packet_len(odp_packet_hdr_t *pkt_hdr)
{
	uint32_t pkt_len = pkt_hdr->frame_len;
	odp_packet_hdr_t *ref_hdr = pkt_hdr->ref_hdr;

	while (ref_hdr) {
		pkt_len += (pkt_hdr->ref_len - pkt_hdr->ref_offset);
		pkt_hdr = ref_hdr;
		ref_hdr = ref_hdr->ref_hdr;
	}

	return pkt_len;
}

static inline uint32_t packet_ref_count(odp_packet_hdr_t *pkt_hdr)
{
	/* Breach the atomic type to do a peek at the ref count. This
	 * is used to bypass atomic operations if ref_count == 1 for
	 * performance reasons.
	 */
	return pkt_hdr->ref_count.v;
}

static inline void packet_ref_count_set(odp_packet_hdr_t *pkt_hdr, uint32_t n)
{
	/* Only used during init when there are no other possible
	 * references to this pkt, so avoid the "atomic" overhead by
	 * a controlled breach of the atomic type here. This saves
	 * over 10% of the pathlength in routines like packet_alloc().
	 */
	pkt_hdr->ref_count.v = n;
}

static inline void packet_set_len(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	ODP_ASSERT(packet_ref_count(pkt_hdr) == 1);

	pkt_hdr->frame_len = len;
	pkt_hdr->unshared_len = len;
}

/* Forward declarations */
int _odp_packet_copy_md_to_packet(odp_packet_t srcpkt, odp_packet_t dstpkt);

/* Packet alloc of pktios */
int packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
		       odp_packet_t pkt[], int max_num);

/* Perform packet parse up to a given protocol layer */
int packet_parse_layer(odp_packet_hdr_t *pkt_hdr,
		       odp_pktio_parser_layer_t layer);

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
			uint32_t pkt_len, uint32_t seg_len,
			odp_pktio_parser_layer_t layer);

int _odp_cls_parse(odp_packet_hdr_t *pkt_hdr, const uint8_t *parseptr);

int _odp_packet_set_data(odp_packet_t pkt, uint32_t offset,
			 uint8_t c, uint32_t len);

int _odp_packet_cmp_data(odp_packet_t pkt, uint32_t offset,
			 const void *s, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
