/* Copyright (c) 2015-2018, Linaro Limited
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

typedef uint8_t odp_packet_seg_t;

/* or it will be provided by packet_inlines.h */
#define _ODP_HAVE_PACKET_SEG_NDX	1

static inline uint8_t _odp_packet_seg_to_ndx(odp_packet_seg_t seg)
{
	return (uint8_t)seg;
}

static inline odp_packet_seg_t _odp_packet_seg_from_ndx(uint8_t ndx)
{
	return (odp_packet_seg_t)ndx;
}

#define ODP_PACKET_SEG_INVALID ((odp_packet_seg_t)-1)

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

#define _ODP_INLINE static inline
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/packet_inlines_api.h>

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
