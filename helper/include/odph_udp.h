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

#include <odp_align.h>
#include <odp_debug.h>
#include <odp_byteorder.h>

/** UDP header length */
#define ODPH_UDPHDR_LEN 8

/** UDP header */
typedef struct ODP_PACKED {
	uint16be_t src_port; /**< Source port */
	uint16be_t dst_port; /**< Destination port */
	uint16be_t length;   /**< UDP datagram length in bytes (header+data) */
	uint16be_t chksum;   /**< UDP header and data checksum (0 if not used)*/
} odph_udphdr_t;

/** UDP pseudo header */
typedef struct ODPH_PACKET {
	uint32be_t src_addr; /**< Source addr */
	uint32be_t dst_addr; /**< Destination addr */
	uint8_t pad;	     /**< pad byte */
	uint8_t proto;	     /**< UDP protocol */
	uint16be_t length;   /**< data length */
} odph_udpphdr_t;

/**
 * UDP checksum
 *
 * This function uses odp packet to calc checksum
 *
 * @param pkt  calculate chksum for pkt
 * @return  checksum value
 */
static inline uint16_t odph_ipv4_udp_chksum(odp_packet_t pkt)
{
	uint32_t sum = 0;
	odph_udpphdr_t phdr;
	odph_udphdr_t *udph;
	odph_ipv4hdr_t *iph;
	uint16_t udplen;

	if (!odp_packet_l3_offset(pkt))
		return 0;

	if (!odp_packet_l4_offset(pkt))
		return 0;

	iph = (odph_ipv4hdr_t *)odp_packet_l3(pkt);
	udph = (odph_udphdr_t *)odp_packet_l4(pkt);
	udplen = odp_be_to_cpu_16(udph->length);

	/* the source ip */
	phdr.src_addr = iph->src_addr;
	/* the dest ip */
	phdr.dst_addr = iph->dst_addr;
	/* proto */
	phdr.pad = 0;
	phdr.proto = ODPH_IPPROTO_UDP;
	/* the length */
	phdr.length = udph->length;

	/* calc UDP pseudo header chksum */
	sum = (__odp_force uint32_t) odp_chksum(&phdr, sizeof(odph_udpphdr_t));
	/* calc udp header and data chksum */
	sum += (__odp_force uint32_t) odp_chksum(udph, udplen);

	/* Fold sum to 16 bits: add carrier to result */
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	/* set computation result */
	sum = (sum == 0x0) ? 0xFFFF : sum;

	return sum;
}

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(odph_udphdr_t) == ODPH_UDPHDR_LEN, "ODPH_UDPHDR_T__SIZE_ERROR");

#ifdef __cplusplus
}
#endif

#endif
