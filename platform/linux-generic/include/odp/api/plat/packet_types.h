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

#define ODP_PACKET_INVALID _odp_cast_scalar(odp_packet_t, 0)

#define ODP_PACKET_OFFSET_INVALID (0x0fffffff)

typedef uint8_t odp_packet_seg_t;

#define ODP_PACKET_SEG_INVALID ((odp_packet_seg_t)-1)

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

/** @internal Packet header field offsets for inline functions */
typedef struct _odp_packet_inline_offset_t {
	/** @internal field offset */
	size_t data;
	/** @internal field offset */
	size_t seg_len;
	/** @internal field offset */
	size_t frame_len;
	/** @internal field offset */
	size_t headroom;
	/** @internal field offset */
	size_t tailroom;
	/** @internal field offset */
	size_t pool;
	/** @internal field offset */
	size_t input;
	/** @internal field offset */
	size_t segcount;
	/** @internal field offset */
	size_t user_ptr;
	/** @internal field offset */
	size_t user_area;
	/** @internal field offset */
	size_t user_area_size;
	/** @internal field offset */
	size_t flow_hash;
	/** @internal field offset */
	size_t timestamp;
	/** @internal field offset */
	size_t input_flags;

} _odp_packet_inline_offset_t;

/** @internal Packet input & protocol flags */
typedef union {
	/** All input flags */
	uint64_t all;

	struct {
		uint64_t parsed_l2:1; /**< L2 parsed */
		uint64_t dst_queue:1; /**< Dst queue present */

		uint64_t flow_hash:1; /**< Flow hash present */
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
