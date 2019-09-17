/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_API_ABI_PACKET_H_
#define ODP_API_ABI_PACKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

/** @ingroup odp_packet
 *  @{
 */

typedef ODP_HANDLE_T(odp_packet_t);

#define ODP_PACKET_INVALID _odp_cast_scalar(odp_packet_t, 0)

#define ODP_PACKET_OFFSET_INVALID 0xffff

typedef ODP_HANDLE_T(odp_packet_seg_t);

#define ODP_PACKET_SEG_INVALID _odp_cast_scalar(odp_packet_seg_t, 0)

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

typedef struct odp_packet_parse_result_flag_t {
	union {
		uint64_t all;

		struct {
			uint64_t has_error    : 1;
			uint64_t has_l2_error : 1;
			uint64_t has_l3_error : 1;
			uint64_t has_l4_error : 1;
			uint64_t has_l2 : 1;
			uint64_t has_l3 : 1;
			uint64_t has_l4 : 1;
			uint64_t has_eth : 1;
			uint64_t has_eth_bcast : 1;
			uint64_t has_eth_mcast : 1;
			uint64_t has_jumbo : 1;
			uint64_t has_vlan : 1;
			uint64_t has_vlan_qinq : 1;
			uint64_t has_arp : 1;
			uint64_t has_ipv4 : 1;
			uint64_t has_ipv6 : 1;
			uint64_t has_ip_bcast : 1;
			uint64_t has_ip_mcast : 1;
			uint64_t has_ipfrag : 1;
			uint64_t has_ipopt : 1;
			uint64_t has_ipsec : 1;
			uint64_t has_udp : 1;
			uint64_t has_tcp : 1;
			uint64_t has_sctp : 1;
			uint64_t has_icmp : 1;
		};
	};

} odp_packet_parse_result_flag_t;

#include <odp/api/plat/packet_inlines.h>

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
