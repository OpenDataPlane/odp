/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
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

#include <odp_align.h>
#include <odp_debug.h>
#include <odp_buffer_internal.h>
#include <odp_buffer_pool_internal.h>
#include <odp_packet.h>
#include <odp_packet_io.h>

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

ODP_STATIC_ASSERT(sizeof(input_flags_t) == sizeof(uint32_t), "INPUT_FLAGS_SIZE_ERROR");

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

ODP_STATIC_ASSERT(sizeof(error_flags_t) == sizeof(uint32_t), "ERROR_FLAGS_SIZE_ERROR");

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

ODP_STATIC_ASSERT(sizeof(output_flags_t) == sizeof(uint32_t), "OUTPUT_FLAGS_SIZE_ERROR");

/**
 * Internal Packet header
 */
struct odp_pkthdr {
	/* common buffer header */
	struct odp_bufhdr buf_hdr;

	input_flags_t  input_flags;
	error_flags_t  error_flags;
	output_flags_t output_flags;

	uint16_t frame_offset; /**< offset to start of frame, even on error */
	uint16_t l2_offset; /**< offset to L2 hdr, e.g. Eth */
	uint16_t l3_offset; /**< offset to L3 hdr, e.g. IPv4, IPv6 */
	uint16_t l4_offset; /**< offset to L4 hdr (TCP, UDP, SCTP, also ICMP) */

	uint32_t frame_len;

	odp_pktio_t input;

	struct {
		int16_t saved_buf_offset;
		uint32_t hash_offset;
		union {
			struct {
			} enc;
			struct {
				uint32_t hash_tag[5];
			} dec;
		};

	} crypto;

};

ODP_STATIC_ASSERT(sizeof(struct odp_pkthdr) <= ODP_CACHE_LINE_SIZE,
		  "PACKET_HDR_T_SIZE_ERROR");

/**
 * Return the packet header
 */
static inline struct odp_pkthdr *odp_packet_hdr(odp_packet_t pkt)
{
	odp_buffer_t buf = odp_buffer_from_packet(pkt);
	return (struct odp_pkthdr *)odp_buffer_hdr(buf);
}

/**
 * Parse packet and set internal metadata
 */
void odp_packet_parse(odp_packet_t pkt, size_t len, size_t l2_offset);

static inline void odp_pr_packet(int level, odp_packet_t pkt)
{
	if (level <= ODP_PRINT_LEVEL)
		odp_packet_print(pkt);
}

#define odp_pr_err_packet(...)  \
		odp_pr_packet(ODP_PRINT_LEVEL_ERR, ##__VA_ARGS__)
#define odp_pr_dbg_packet(...)  \
		odp_pr_packet(ODP_PRINT_LEVEL_DBG, ##__VA_ARGS__)
#define odp_pr_vdbg_packet(...) \
		odp_pr_packet(ODP_PRINT_LEVEL_VDBG, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
