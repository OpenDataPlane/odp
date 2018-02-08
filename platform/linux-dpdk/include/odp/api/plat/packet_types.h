/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_PACKET_TYPES_H_
#define ODP_PACKET_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 1
#include <odp/api/abi/packet.h>
#else

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

/** @ingroup odp_packet
 *  @{
 */

typedef ODP_HANDLE_T(odp_packet_t);

#define ODP_PACKET_INVALID _odp_cast_scalar(odp_packet_t, NULL)

#define ODP_PACKET_OFFSET_INVALID 0xffff

typedef ODP_HANDLE_T(odp_packet_seg_t);

#define ODP_PACKET_SEG_INVALID _odp_cast_scalar(odp_packet_seg_t, NULL)

typedef enum {
	ODP_PACKET_GREEN = 0,
	ODP_PACKET_YELLOW = 1,
	ODP_PACKET_RED = 2,
	ODP_PACKET_ALL_COLORS = 3,
} odp_packet_color_t;

#define ODP_NUM_PACKET_COLORS 3

/**
 * @}
 */

#endif

/** @internal Packet field accessor */
#define _odp_pkt_get(pkt, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)pkt + _odp_packet_inline.field))

/** @internal Packet header field offsets for inline functions */
typedef struct _odp_packet_inline_offset_t {
	/** @internal field offset */
	uint16_t mb;
	/** @internal field offset */
	uint16_t pool;
	/** @internal field offset */
	uint16_t input;
	/** @internal field offset */
	uint16_t user_ptr;
	/** @internal field offset */
	uint16_t l2_offset;
	/** @internal field offset */
	uint16_t l3_offset;
	/** @internal field offset */
	uint16_t l4_offset;
	/** @internal field offset */
	uint16_t timestamp;
	/** @internal field offset */
	uint16_t input_flags;
	/** @internal field offset */
	uint16_t buf_addr;
	/** @internal field offset */
	uint16_t data;
	/** @internal field offset */
	uint16_t pkt_len;
	/** @internal field offset */
	uint16_t seg_len;
	/** @internal field offset */
	uint16_t nb_segs;
	/** @internal offset */
	uint16_t udata;
	/** @internal field offset */
	uint16_t rss;
	/** @internal field offset */
	uint16_t ol_flags;
	/** @internal rss hash result set */
	uint64_t rss_flag;

} _odp_packet_inline_offset_t;

/** @internal Packet input & protocol flags */
typedef union {
	/** All input flags */
	uint64_t all;

	/** Individual input flags */
	struct {
		uint64_t dst_queue:1; /**< Dst queue present */

		uint64_t timestamp:1; /**< Timestamp present */

		uint64_t l2:1;        /**< known L2 protocol present */
		uint64_t l3:1;        /**< known L3 protocol present */
		uint64_t l4:1;        /**< known L4 protocol present */

		uint64_t eth:1;       /**< Ethernet */
		uint64_t eth_bcast:1; /**< Ethernet broadcast */
		uint64_t eth_mcast:1; /**< Ethernet multicast */
		uint64_t jumbo:1;     /**< Jumbo frame */
		uint64_t vlan:1;      /**< VLAN hdr found */
		uint64_t vlan_qinq:1; /**< Stacked VLAN found, QinQ */

		uint64_t snap:1;      /**< SNAP */
		uint64_t arp:1;       /**< ARP */

		uint64_t ipv4:1;      /**< IPv4 */
		uint64_t ipv6:1;      /**< IPv6 */
		uint64_t ip_bcast:1;  /**< IP broadcast */
		uint64_t ip_mcast:1;  /**< IP multicast */
		uint64_t ipfrag:1;    /**< IP fragment */
		uint64_t ipopt:1;     /**< IP optional headers */

		uint64_t ipsec:1;     /**< IPSec packet. Required by the
					   odp_packet_has_ipsec_set() func. */
		uint64_t ipsec_ah:1;  /**< IPSec authentication header */
		uint64_t ipsec_esp:1; /**< IPSec encapsulating security
					   payload */
		uint64_t udp:1;       /**< UDP */
		uint64_t tcp:1;       /**< TCP */
		uint64_t tcpopt:1;    /**< TCP options present */
		uint64_t sctp:1;      /**< SCTP */
		uint64_t icmp:1;      /**< ICMP */

		uint64_t color:2;     /**< Packet color for traffic mgmt */
		uint64_t nodrop:1;    /**< Drop eligibility status */
	};
} _odp_packet_input_flags_t;

#ifdef __cplusplus
}
#endif

#endif
