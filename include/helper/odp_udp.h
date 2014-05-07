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

#ifndef ODP_UDP_H_
#define ODP_UDP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_align.h>
#include <odp_debug.h>
#include <odp_byteorder.h>

/** UDP header length */
#define ODP_UDPHDR_LEN 8

/** UDP header */
typedef struct ODP_PACKED {
	uint16be_t src_port; /**< Source port */
	uint16be_t dst_port; /**< Destination port */
	uint16be_t length;   /**< UDP datagram length in bytes (header+data) */
	uint16be_t chksum;   /**< UDP header and data checksum (0 if not used)*/
} odp_udphdr_t;

/**
 * UDP checksum
 *
 * This function uses odp packet to calc checksum
 *
 * @param pkt  calculate chksum for pkt
 * @return  checksum value
 */
static inline uint16_t odp_ipv4_udp_chksum(odp_packet_t pkt)
{
	unsigned long sum = 0;
	odp_udphdr_t *udph;
	odp_ipv4hdr_t *iph;
	uint8_t *buf;
	unsigned short udplen;
	uint16_t chksum;

	if (!odp_packet_l3_offset(pkt))
		return 0;

	if (!odp_packet_l4_offset(pkt))
		return 0;

	iph = (odp_ipv4hdr_t *)odp_packet_l3(pkt);
	udph = (odp_udphdr_t *)odp_packet_l4(pkt);
	buf = (uint8_t *)udph;
	udplen = odp_be_to_cpu_16(udph->length);

	/* the source ip */
	sum += (iph->src_addr >> 16) & 0xFFFF;
	sum += (iph->src_addr) & 0xFFFF;
	/* the dest ip */
	sum += (iph->dst_addr >> 16) & 0xFFFF;
	sum += (iph->dst_addr) & 0xFFFF;
	sum += odp_cpu_to_be_16(ODP_IPPROTO_UDP);
	/* the length */
	sum += udph->length;

	while (udplen > 1) {
		sum += *buf++;
		udplen -= 1;
	}
	/* if any bytes left, pad the bytes and add */
	if (udplen > 0)
		sum += ((*buf)&odp_cpu_to_be_16(0xFF00));

	/* Fold sum to 16 bits: add carrier to result */
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	sum = ~sum;
	/* set computation result */
	chksum = ((unsigned short)sum == 0x0) ? 0xFFFF
			  : (unsigned short)sum;

	return chksum;
}

/** @internal Compile time assert */
ODP_ASSERT(sizeof(odp_udphdr_t) == ODP_UDPHDR_LEN, ODP_UDPHDR_T__SIZE_ERROR);

#ifdef __cplusplus
}
#endif

#endif
