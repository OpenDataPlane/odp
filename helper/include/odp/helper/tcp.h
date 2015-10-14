/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP TCP header
 */

#ifndef ODPH_TCP_H_
#define ODPH_TCP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/align.h>
#include <odp/debug.h>
#include <odp/byteorder.h>

/** @addtogroup odph_header ODPH HEADER
 *  @{
 */

#define ODPH_TCPHDR_LEN 20 /**< Min length of TCP header (no options) */

/** TCP header */
typedef struct ODP_PACKED {
	uint16be_t src_port; /**< Source port */
	uint16be_t dst_port; /**< Destination port */
	uint32be_t seq_no;   /**< Sequence number */
	uint32be_t ack_no;   /**< Acknowledgment number */
	union {
		uint16be_t doffset_flags;
#if defined(ODP_BIG_ENDIAN_BITFIELD)
		struct {
			uint16be_t rsvd1:8;
			uint16be_t flags:8; /**< TCP flags as a byte */
		};
		struct {
			uint16be_t hl:4;    /**< Hdr len, in words */
			uint16be_t rsvd3:4; /**< Reserved */
			uint16be_t cwr:1;
			uint16be_t ece:1;
			uint16be_t urg:1;
			uint16be_t ack:1;
			uint16be_t psh:1;
			uint16be_t rst:1;
			uint16be_t syn:1;
			uint16be_t fin:1;
		};
#elif defined(ODP_LITTLE_ENDIAN_BITFIELD)
		struct {
			uint16be_t flags:8;
			uint16be_t rsvd1:8; /**< TCP flags as a byte */
		};
		struct {
			uint16be_t rsvd3:4; /**< Reserved */
			uint16be_t hl:4;    /**< Hdr len, in words */
			uint16be_t fin:1;
			uint16be_t syn:1;
			uint16be_t rst:1;
			uint16be_t psh:1;
			uint16be_t ack:1;
			uint16be_t urg:1;
			uint16be_t ece:1;
			uint16be_t cwr:1;
		};

#else
#error "Endian BitField order not defined!"
#endif
	};
	uint16be_t window; /**< Window size */
	uint16be_t cksm;   /**< Checksum */
	uint16be_t urgptr; /**< Urgent pointer */
} odph_tcphdr_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
