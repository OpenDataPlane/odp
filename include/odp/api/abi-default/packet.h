/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ABI_PACKET_H_
#define ODP_ABI_PACKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_packet_t;

/** @internal Dummy  type for strong typing */
typedef struct { char dummy; /**< *internal Dummy */ } _odp_abi_packet_seg_t;

/** @ingroup odp_packet
 *  @{
 */

typedef _odp_abi_packet_t *odp_packet_t;
typedef _odp_abi_packet_seg_t *odp_packet_seg_t;

#define ODP_PACKET_INVALID        ((odp_packet_t)0)
#define ODP_PACKET_SEG_INVALID    ((odp_packet_seg_t)0)
#define ODP_PACKET_OFFSET_INVALID 0xffff

typedef uint8_t odp_proto_l2_type_t;

#define ODP_PROTO_L2_TYPE_NONE   0
#define ODP_PROTO_L2_TYPE_ETH    1

typedef uint8_t odp_proto_l3_type_t;

#define ODP_PROTO_L3_TYPE_NONE   0
#define ODP_PROTO_L3_TYPE_ARP    1
#define ODP_PROTO_L3_TYPE_RARP   2
#define ODP_PROTO_L3_TYPE_MPLS   3
#define ODP_PROTO_L3_TYPE_IPV4   4
#define ODP_PROTO_L3_TYPE_IPV6   6

typedef uint8_t odp_proto_l4_type_t;

/* Numbers from IANA Assigned Internet Protocol Numbers list */
#define ODP_PROTO_L4_TYPE_NONE      0
#define ODP_PROTO_L4_TYPE_ICMPV4    1
#define ODP_PROTO_L4_TYPE_IGMP      2
#define ODP_PROTO_L4_TYPE_IPV4      4
#define ODP_PROTO_L4_TYPE_TCP       6
#define ODP_PROTO_L4_TYPE_UDP       17
#define ODP_PROTO_L4_TYPE_IPV6      41
#define ODP_PROTO_L4_TYPE_GRE       47
#define ODP_PROTO_L4_TYPE_ESP       50
#define ODP_PROTO_L4_TYPE_AH        51
#define ODP_PROTO_L4_TYPE_ICMPV6    58
#define ODP_PROTO_L4_TYPE_NO_NEXT   59
#define ODP_PROTO_L4_TYPE_IPCOMP    108
#define ODP_PROTO_L4_TYPE_SCTP      132
#define ODP_PROTO_L4_TYPE_ROHC      142

typedef enum {
	ODP_PACKET_GREEN = 0,
	ODP_PACKET_YELLOW = 1,
	ODP_PACKET_RED = 2,
	ODP_PACKET_ALL_COLORS = 3,
} odp_packet_color_t;

#define ODP_NUM_PACKET_COLORS 3

/** Parse result flags */
typedef struct odp_packet_parse_result_flag_t {
	/** Flags union */
	union {
		/** All flags as a 64 bit word */
		uint64_t all;

		/** Flags as a bitfield struct */
		struct {
			/** @see odp_packet_has_error() */
			uint64_t has_error    : 1;
			/** @see odp_packet_has_l2_error() */
			uint64_t has_l2_error : 1;
			/** @see odp_packet_has_l3_error() */
			uint64_t has_l3_error : 1;
			/** @see odp_packet_has_l4_error() */
			uint64_t has_l4_error : 1;
			/** @see odp_packet_has_l2() */
			uint64_t has_l2 : 1;
			/** @see odp_packet_has_l3() */
			uint64_t has_l3 : 1;
			/** @see odp_packet_has_l4() */
			uint64_t has_l4 : 1;
			/** @see odp_packet_has_eth() */
			uint64_t has_eth : 1;
			/** @see odp_packet_has_eth_bcast() */
			uint64_t has_eth_bcast : 1;
			/** @see odp_packet_has_eth_mcast() */
			uint64_t has_eth_mcast : 1;
			/** @see odp_packet_has_jumbo() */
			uint64_t has_jumbo : 1;
			/** @see odp_packet_has_vlan() */
			uint64_t has_vlan : 1;
			/** @see odp_packet_has_vlan_qinq() */
			uint64_t has_vlan_qinq : 1;
			/** @see odp_packet_has_arp() */
			uint64_t has_arp : 1;
			/** @see odp_packet_has_ipv4() */
			uint64_t has_ipv4 : 1;
			/** @see odp_packet_has_ipv6() */
			uint64_t has_ipv6 : 1;
			/** @see odp_packet_has_ip_bcast() */
			uint64_t has_ip_bcast : 1;
			/** @see odp_packet_has_ip_mcast() */
			uint64_t has_ip_mcast : 1;
			/** @see odp_packet_has_ipfrag() */
			uint64_t has_ipfrag : 1;
			/** @see odp_packet_has_ipopt() */
			uint64_t has_ipopt : 1;
			/** @see odp_packet_has_ipsec() */
			uint64_t has_ipsec : 1;
			/** @see odp_packet_has_udp() */
			uint64_t has_udp : 1;
			/** @see odp_packet_has_tcp() */
			uint64_t has_tcp : 1;
			/** @see odp_packet_has_sctp() */
			uint64_t has_sctp : 1;
			/** @see odp_packet_has_icmp() */
			uint64_t has_icmp : 1;
		};
	};

} odp_packet_parse_result_flag_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
