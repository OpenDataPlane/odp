/* Copyright (c) 2014, Linaro Limited
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

#include <odp/align.h>
#include <odp_debug_internal.h>
#include <odp/debug.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp/packet.h>
#include <odp/packet_io.h>

/**
 * Packet input & protocol flags
 */
typedef union {
	/* All input flags */
	uint32_t all;

	struct {
		/* Bitfield flags for each protocol */
		uint32_t l2:1;        /**< known L2 protocol present */
		uint32_t l3:1;        /**< known L3 protocol present */
		uint32_t l4:1;        /**< known L4 protocol present */

		uint32_t eth:1;       /**< Ethernet */
		uint32_t jumbo:1;     /**< Jumbo frame */
		uint32_t vlan:1;      /**< VLAN hdr found */
		uint32_t vlan_qinq:1; /**< Stacked VLAN found, QinQ */

		uint32_t arp:1;       /**< ARP */

		uint32_t ipv4:1;      /**< IPv4 */
		uint32_t ipv6:1;      /**< IPv6 */
		uint32_t ipfrag:1;    /**< IP fragment */
		uint32_t ipopt:1;     /**< IP optional headers */
		uint32_t ipsec:1;     /**< IPSec decryption may be needed */

		uint32_t udp:1;       /**< UDP */
		uint32_t tcp:1;       /**< TCP */
		uint32_t sctp:1;      /**< SCTP */
		uint32_t icmp:1;      /**< ICMP */
	};
} input_flags_t;

_ODP_STATIC_ASSERT(sizeof(input_flags_t) == sizeof(uint32_t),
		   "INPUT_FLAGS_SIZE_ERROR");

/**
 * Packet error flags
 */
typedef union {
	/* All error flags */
	uint32_t all;

	struct {
		/* Bitfield flags for each detected error */
		uint32_t frame_len:1; /**< Frame length error */
		uint32_t l2_chksum:1; /**< L2 checksum error, checks TBD */
		uint32_t ip_err:1;    /**< IP error,  checks TBD */
		uint32_t tcp_err:1;   /**< TCP error, checks TBD */
		uint32_t udp_err:1;   /**< UDP error, checks TBD */
	};
} error_flags_t;

_ODP_STATIC_ASSERT(sizeof(error_flags_t) == sizeof(uint32_t),
		   "ERROR_FLAGS_SIZE_ERROR");

/**
 * Packet output flags
 */
typedef union {
	/* All output flags */
	uint32_t all;

	struct {
		/* Bitfield flags for each output option */
		uint32_t l4_chksum:1; /**< Request L4 checksum calculation */
	};
} output_flags_t;

_ODP_STATIC_ASSERT(sizeof(output_flags_t) == sizeof(uint32_t),
		   "OUTPUT_FLAGS_SIZE_ERROR");

/**
 * Internal Packet header
 */
typedef struct {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;

	input_flags_t  input_flags;
	error_flags_t  error_flags;
	output_flags_t output_flags;

	uint32_t frame_offset; /**< offset to start of frame, even on error */
	uint32_t l2_offset; /**< offset to L2 hdr, e.g. Eth */
	uint32_t l3_offset; /**< offset to L3 hdr, e.g. IPv4, IPv6 */
	uint32_t l4_offset; /**< offset to L4 hdr (TCP, UDP, SCTP, also ICMP) */

	uint64_t user_ctx;  /**< user context */

	odp_pktio_t input;
} odp_packet_hdr_t;

/**
 * Return the packet header
 */
static inline odp_packet_hdr_t *odp_packet_hdr(odp_packet_t pkt)
{
	return (odp_packet_hdr_t *)pkt;
}

/**
 * Parse packet and set internal metadata
 */
void odp_packet_parse(odp_packet_t pkt, size_t len, size_t l2_offset);

/* Forward declarations */
static inline int _odp_packet_copy_to_packet(odp_packet_t srcpkt ODP_UNUSED, uint32_t srcoffset ODP_UNUSED,
			       odp_packet_t dstpkt ODP_UNUSED, uint32_t dstoffset ODP_UNUSED,
			       uint32_t len ODP_UNUSED) {
	ODP_UNIMPLEMENTED();
	ODP_ABORT("");
	return 0;
}

static inline int _odp_packet_parse(odp_packet_t pkt ODP_UNUSED) {
	ODP_UNIMPLEMENTED();
	ODP_ABORT("");
	return 0;
}

void _odp_packet_copy_md_to_packet(odp_packet_t srcpkt, odp_packet_t dstpkt);

/* Convert a buffer handle to a packet handle */
odp_packet_t _odp_packet_from_buffer(odp_buffer_t buf);

#ifdef __cplusplus
}
#endif

#endif
