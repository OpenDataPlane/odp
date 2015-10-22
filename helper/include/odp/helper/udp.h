/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP UDP header
 */

#ifndef ODPH_UDP_H_
#define ODPH_UDP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/align.h>
#include <odp/debug.h>
#include <odp/byteorder.h>


/** @addtogroup odph_header ODPH HEADER
 *  @{
 */

/** UDP header length */
#define ODPH_UDPHDR_LEN 8

/** UDP header */
typedef struct ODP_PACKED {
	uint16be_t src_port; /**< Source port */
	uint16be_t dst_port; /**< Destination port */
	uint16be_t length;   /**< UDP datagram length in bytes (header+data) */
	uint16be_t chksum;   /**< UDP header and data checksum (0 if not used)*/
} odph_udphdr_t;

/**
 * UDP checksum
 *
 * This function uses odp packet to calc checksum
 *
 * @param pkt  calculate chksum for pkt
 * @return  checksum value in CPU endianness
 */
static inline uint16_t odph_ipv4_udp_chksum(odp_packet_t pkt)
{
	uint32_t sum;
	odph_udphdr_t *udph;
	odph_ipv4hdr_t *iph;
	uint16_t udplen, *buf;

	if (odp_packet_l4_offset(pkt) == ODP_PACKET_OFFSET_INVALID)
		return 0;

	iph = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	udph = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udplen = odp_be_to_cpu_16(udph->length);

	/* 32-bit sum of all 16-bit words covered by UDP chksum */
	sum = (iph->src_addr & 0xFFFF) + (iph->src_addr >> 16) +
	      (iph->dst_addr & 0xFFFF) + (iph->dst_addr >> 16) +
	      odp_be_to_cpu_16(iph->proto) + udph->length;
	for (buf = (uint16_t *)((void *)udph); udplen > 1; udplen -= 2)
		sum += *buf++;
	if (udplen) /* If length is not a multiple of 2 bytes */
		sum += odp_be_to_cpu_16(*((uint8_t *)buf) << 8);

	/* Fold sum to 16 bits: add carrier to result */
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum += (sum >> 16);

	/* 1's complement */
	sum = ~sum;

	/* set computation result in CPU endianness*/
	return (sum == 0x0) ? 0xFFFF : odp_be_to_cpu_16(sum);
}

/** @internal Compile time assert */
_ODP_STATIC_ASSERT(sizeof(odph_udphdr_t) == ODPH_UDPHDR_LEN, "ODPH_UDPHDR_T__SIZE_ERROR");

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
