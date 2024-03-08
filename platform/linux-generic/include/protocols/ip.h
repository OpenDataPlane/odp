/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP IP header
 */

#ifndef ODP_IP_H_
#define ODP_IP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/byteorder.h>
#include <odp/api/debug.h>

/** @addtogroup odp_header ODP HEADER
 *  @{
 */

#define _ODP_IPV4             4  /**< IP version 4 */
#define _ODP_IPV4HDR_LEN     20  /**< Min length of IP header (no options) */
#define _ODP_IPV4HDR_IHL_MIN  5  /**< Minimum IHL value*/
#define _ODP_IPV4ADDR_LEN     4  /**< IPv4 address length in bytes */

/** The one byte IPv4 tos or IPv6 tc field is composed of the following two
 * subfields - a six bit Differentiated Service Code Point (DSCP) and a two
 * bit Explicit Congestion Notification (ECN) subfield.  The following
 * constants can be used to extract or modify these fields.  Despite the
 * name prefix being _ODP_IP_TOS_* these constants apply equally well for
 * the IPv6 Traffic Class (tc) field.
 */
#define _ODP_IP_TOS_MAX_DSCP   63    /**< 6-bit DSCP field has max value 63  */
#define _ODP_IP_TOS_DSCP_MASK  0xFC  /**< DSCP field is in bits <7:2>  */
#define _ODP_IP_TOS_DSCP_SHIFT 2     /**< DSCP field is shifted letf by 2  */
#define _ODP_IP_TOS_MAX_ECN    3     /**< 2-bit ECN field has max value 3  */
#define _ODP_IP_TOS_ECN_MASK   0x03  /**< ECN field is in bits <1:0>  */
#define _ODP_IP_TOS_ECN_SHIFT  0     /**< ECN field is not shifted.  */

/** The following constants give names to the four possible ECN values,
 * as described in RFC 3168.
 */
#define _ODP_IP_ECN_NOT_ECT  0  /**< 0 indicates not participating in ECN */
#define _ODP_IP_ECN_ECT1     1  /**< Indicates no congestion seen yet */
#define _ODP_IP_ECN_ECT0     2  /**< Indicates no congestion seen yet */
#define _ODP_IP_ECN_CE       3  /**< Used to signal Congestion Experienced */

/** @internal Returns IPv4 version */
#define _ODP_IPV4HDR_VER(ver_ihl) (((ver_ihl) & 0xf0) >> 4)

/** @internal Returns IPv4 header length */
#define _ODP_IPV4HDR_IHL(ver_ihl) ((ver_ihl) & 0x0f)

/** @internal Returns IPv4 DSCP */
#define _ODP_IPV4HDR_DSCP(tos) (((tos) & 0xfc) >> 2)

/** @internal Returns IPv4 Don't fragment */
#define _ODP_IPV4HDR_FLAGS_DONT_FRAG(frag_offset)  ((frag_offset) & 0x4000)

/* IPv4 more fragments flag in the frag_offset field */
#define _ODP_IPV4HDR_FRAG_OFFSET_MORE_FRAGS 0x2000

/** @internal Returns IPv4 fragment offset */
#define _ODP_IPV4HDR_FRAG_OFFSET(frag_offset) ((frag_offset) & 0x1fff)

/** @internal Returns true if IPv4 packet is a fragment */
#define _ODP_IPV4HDR_IS_FRAGMENT(frag_offset) ((frag_offset) & 0x3fff)

/** IPv4 header */
typedef struct ODP_PACKED {
	uint8_t    ver_ihl;     /**< Version / Header length */
	uint8_t    tos;         /**< Type of service */
	odp_u16be_t tot_len;    /**< Total length */
	odp_u16be_t id;         /**< ID */
	odp_u16be_t frag_offset;/**< Fragmentation offset */
	uint8_t    ttl;         /**< Time to live */
	uint8_t    proto;       /**< Protocol */
	odp_u16sum_t chksum;    /**< Checksum */
	odp_u32be_t src_addr;   /**< Source address */
	odp_u32be_t dst_addr;   /**< Destination address */
} _odp_ipv4hdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(_odp_ipv4hdr_t) == _ODP_IPV4HDR_LEN,
		  "_ODP_IPV4HDR_T__SIZE_ERROR");

/** IPv6 version */
#define _ODP_IPV6 6

/** IPv6 header length */
#define _ODP_IPV6HDR_LEN 40

/** IPv6 address length in bytes */
#define _ODP_IPV6ADDR_LEN 16

/** The following constants can be used to access the three subfields
 * of the 4 byte ver_tc_flow field - namely the four bit Version subfield,
 * the eight bit Traffic Class subfield (TC) and the twenty bit Flow Label
 * subfield.  Note that the IPv6 TC field is analogous to the IPv4 TOS
 * field and is composed of the DSCP and ECN subfields.  Use the _ODP_IP_TOS_*
 * constants above to access these subfields.
 */
#define _ODP_IPV6HDR_VERSION_MASK     0xF0000000 /**< Version field bit mask */
#define _ODP_IPV6HDR_VERSION_SHIFT    28         /**< Version field shift */
#define _ODP_IPV6HDR_TC_MASK          0x0FF00000 /**< TC field bit mask */
#define _ODP_IPV6HDR_TC_SHIFT         20         /**< TC field shift */
#define _ODP_IPV6HDR_FLOW_LABEL_MASK  0x000FFFFF /**< Flow Label bit mask */
#define _ODP_IPV6HDR_FLOW_LABEL_SHIFT 0          /**< Flow Label shift */

/** @internal Returns IPv6 DSCP */
#define _ODP_IPV6HDR_DSCP(ver_tc_flow) \
	(uint8_t)((((ver_tc_flow) & 0x0fc00000) >> 22) & 0xff)

/**
 * Ipv6 address
 */
typedef union ODP_PACKED {
	uint8_t		u8[16];
	odp_u16be_t	u16[8];
	odp_u32be_t	u32[4];
	odp_u64be_t	u64[2];
} _odp_ipv6_addr_t;

/**
 * IPv6 header
 */
typedef struct ODP_PACKED {
	odp_u32be_t ver_tc_flow; /**< Version / Traffic class / Flow label */
	odp_u16be_t payload_len; /**< Payload length */
	uint8_t    next_hdr;     /**< Next header */
	uint8_t    hop_limit;    /**< Hop limit */
	_odp_ipv6_addr_t src_addr; /**< Source address */
	_odp_ipv6_addr_t dst_addr; /**< Destination address */
} _odp_ipv6hdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(_odp_ipv6hdr_t) == _ODP_IPV6HDR_LEN,
		  "_ODP_IPV6HDR_T__SIZE_ERROR");

/**
 * IPv6 Header extensions
 */
typedef struct ODP_PACKED {
	uint8_t    next_hdr;     /**< Protocol of next header */
	uint8_t    ext_len;      /**< Length of this extension in 8 byte units,
				    not counting first 8 bytes, so 0 = 8 bytes
				    1 = 16 bytes, etc. */
	uint8_t    filler[6];    /**< Fill out first 8 byte segment */
} _odp_ipv6hdr_ext_t;

/** @name
 * IP protocol values (IPv4:'proto' or IPv6:'next_hdr')
 * @{*/
#define _ODP_IPPROTO_HOPOPTS 0x00 /**< IPv6 hop-by-hop options */
#define _ODP_IPPROTO_ICMPV4  0x01 /**< Internet Control Message Protocol (1) */
#define _ODP_IPPROTO_IPIP    0x04 /**< IP Encapsulation within IP (4) */
#define _ODP_IPPROTO_TCP     0x06 /**< Transmission Control Protocol (6) */
#define _ODP_IPPROTO_UDP     0x11 /**< User Datagram Protocol (17) */
#define _ODP_IPPROTO_IPV6    0x29 /**< IPv6 Routing header (41) */
#define _ODP_IPPROTO_ROUTE   0x2B /**< IPv6 Routing header (43) */
#define _ODP_IPPROTO_FRAG    0x2C /**< IPv6 Fragment (44) */
#define _ODP_IPPROTO_AH      0x33 /**< Authentication Header (51) */
#define _ODP_IPPROTO_ESP     0x32 /**< Encapsulating Security Payload (50) */
#define _ODP_IPPROTO_ICMPV6  0x3A /**< Internet Control Message Protocol (58) */
#define _ODP_IPPROTO_NO_NEXT 0x3B /**< No Next Header (59) */
#define _ODP_IPPROTO_DEST    0x3C /**< IPv6 Destination header (60) */
#define _ODP_IPPROTO_SCTP    0x84 /**< Stream Control Transmission protocol
				       (132) */
#define _ODP_IPPROTO_INVALID 0xFF /**< Reserved invalid by IANA */

/**@}*/

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif
