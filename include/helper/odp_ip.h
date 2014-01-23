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

#define ODP_IPV4           4  /**< IP version 4 */
#define ODP_IPHDR_LEN     20  /**< Min length of IP header (no options) */
#define ODP_IPHDR_IHL_MIN  5  /**< Minimum IHL value*/

#define ODP_IPHDR_VER(ver_ihl) (((ver_ihl) & 0xf0) >> 4)
#define ODP_IPHDR_IHL(ver_ihl) ((ver_ihl) & 0x0f)

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

ODP_ASSERT(sizeof(odp_ipv4hdr_t) == ODP_IPHDR_LEN, ODP_IPV4HDR_T__SIZE_ERROR);

/* IP header protocol ('proto') field values, a selected few  */
#define ODP_IPPROTO_ICMP 0x01 /**< Internet Control Message Protocol */
#define ODP_IPPROTO_TCP  0x06 /**< Transmission Control Protocol */
#define ODP_IPPROTO_UDP  0x11 /**< User Datagram Protocol */


#ifdef __cplusplus
}
#endif

#endif
