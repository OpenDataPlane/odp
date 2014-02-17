/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
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

#include <odp_align.h>
#include <odp_debug.h>
#include <odp_byteorder.h>

#define ODP_IPV4             4  /**< IP version 4 */
#define ODP_IPV4HDR_LEN     20  /**< Min length of IP header (no options) */
#define ODP_IPV4HDR_IHL_MIN  5  /**< Minimum IHL value*/

#define ODP_IPV4HDR_VER(ver_ihl) (((ver_ihl) & 0xf0) >> 4)
#define ODP_IPV4HDR_IHL(ver_ihl) ((ver_ihl) & 0x0f)
#define ODP_IPV4HDR_FLAGS_DONT_FRAG(frag_offset)  ((frag_offset) & 0x4000)
#define ODP_IPV4HDR_FLAGS_MORE_FRAGS(frag_offset)  ((frag_offset) & 0x2000)
#define ODP_IPV4HDR_FRAG_OFFSET(frag_offset) ((frag_offset) & 0x1fff)

#define ODP_IPV4HDR_IS_FRAGMENT(frag_offset) ((frag_offset) & 0x3fff)

typedef struct ODP_PACKED {
	uint8_t    ver_ihl;
	uint8_t    tos;
	uint16be_t tot_len;
	uint16be_t id;
	uint16be_t frag_offset;
	uint8_t    ttl;
	uint8_t    proto;
	uint16be_t chksum;
	uint32be_t src_addr;
	uint32be_t dst_addr;
} odp_ipv4hdr_t;

ODP_ASSERT(sizeof(odp_ipv4hdr_t) == ODP_IPV4HDR_LEN, ODP_IPV4HDR_T__SIZE_ERROR);


#define ODP_IPV6 6
#define ODP_IPV6HDR_LEN 40

typedef struct ODP_PACKED {
	uint32be_t ver_tc_flow;
	uint16be_t payload_len;
	uint8_t    next_hdr;
	uint8_t    hop_limit;
	uint8_t    src_addr[16];
	uint8_t    dst_addr[16];
} odp_ipv6hdr_t;

ODP_ASSERT(sizeof(odp_ipv6hdr_t) == ODP_IPV6HDR_LEN, ODP_IPV6HDR_T__SIZE_ERROR);

/* IP protocol values (IPv4:'proto' or IPv6:'next_hdr') */
#define ODP_IPPROTO_ICMP 0x01 /**< Internet Control Message Protocol (1) */
#define ODP_IPPROTO_TCP  0x06 /**< Transmission Control Protocol (6) */
#define ODP_IPPROTO_UDP  0x11 /**< User Datagram Protocol (17) */
#define ODP_IPPROTO_SCTP 0x84 /**< Stream Control Transmission Protocol (132) */
#define ODP_IPPROTO_FRAG 0x2C /**< Fragment (44) */
#define ODP_IPPROTO_AH   0x33 /**< Authentication Header (51) */
#define ODP_IPPROTO_ESP  0x32 /**< Encapsulating Security Payload (50) */

#ifdef __cplusplus
}
#endif

#endif
