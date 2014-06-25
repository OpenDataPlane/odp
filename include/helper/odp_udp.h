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

/** UDP pseudo header */
typedef struct ODP_PACKET {
	uint32be_t src_addr; /**< Source addr */
	uint32be_t dst_addr; /**< Destination addr */
	uint8_t pad;	     /**< pad byte */
	uint8_t proto;	     /**< UDP protocol */
	uint16be_t length;   /**< data length */
} odp_udpphdr_t;

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
	uint32_t sum = 0;
	odp_udpphdr_t phdr;
	odp_udphdr_t *udph;
	odp_ipv4hdr_t *iph;
	uint16_t udplen;

	if (!odp_packet_l3_offset(pkt))
		return 0;

	if (!odp_packet_l4_offset(pkt))
		return 0;

	iph = (odp_ipv4hdr_t *)odp_packet_l3(pkt);
	udph = (odp_udphdr_t *)odp_packet_l4(pkt);
	udplen = odp_be_to_cpu_16(udph->length);

	/* the source ip */
	phdr.src_addr = iph->src_addr;
	/* the dest ip */
	phdr.dst_addr = iph->dst_addr;
	/* proto */
	phdr.pad = 0;
	phdr.proto = ODP_IPPROTO_UDP;
	/* the length */
	phdr.length = udph->length;

	/* calc UDP pseudo header chksum */
	sum = odp_chksum(&phdr, sizeof(odp_udpphdr_t));
	/* calc udp header and data chksum */
	sum += odp_chksum(udph, udplen);

	/* Fold sum to 16 bits: add carrier to result */
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	/* set computation result */
	sum = (sum == 0x0) ? 0xFFFF : sum;

	return sum;
}

/** @internal Compile time assert */
ODP_ASSERT(sizeof(odp_udphdr_t) == ODP_UDPHDR_LEN, ODP_UDPHDR_T__SIZE_ERROR);

#ifdef __cplusplus
}
#endif

#endif
