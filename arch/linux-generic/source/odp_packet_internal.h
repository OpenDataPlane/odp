/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet descriptor - implementation internal
 */

#ifndef ODP_PACKET_INTERNAL_H_
#define ODP_PACKET_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_align.h>
#include <odp_debug.h>
#include <odp_buffer_internal.h>
#include <odp_packet.h>
#include <odp_packet_io.h>

typedef struct {
	uint32_t l2:1;
	uint32_t l3:1;
	uint32_t l4:1;

	uint32_t macsec:1;
	uint32_t vlan:1;
	uint32_t vlan_double:1;
	uint32_t ipv4:1;
	uint32_t ipv6:1;
	uint32_t ip_frag:1;
	uint32_t udp:1;
	uint32_t tcp:1;
	uint32_t icmp:1;
} proto_flags_t;

typedef struct {
	uint32_t frame_len:1;
	uint32_t l2_chksum:1;
	uint32_t ip_err:1;
	uint32_t tcp_err:1;
	uint32_t udp_err:1;
} error_flags_t;

typedef struct {
	uint32_t calc_l4_chksum:1;
} output_flags_t;

/**
 * Internal Packet header
 */
typedef struct odp_packet_hdr_t {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;

	proto_flags_t  proto_flags;
	error_flags_t  error_flags;
	output_flags_t output_flags;

	size_t  l2_offset;
	size_t  l3_offset;
	size_t  l4_offset;

	size_t  frame_len;
	odp_pktio_t input;
	/* @TODO: pad needed to ensure that
	 * sizeof(odp_packet_hdr_t) == offsetof(odp_packet_hdr_t, payload)
	 */
	int pad;

/*
	size_t head_room;
	size_t tail_room;
*/

	uint8_t payload[];

} odp_packet_hdr_t;

ODP_ASSERT(sizeof(odp_packet_hdr_t) == ODP_OFFSETOF(odp_packet_hdr_t, payload),
	   ODP_PACKET_HDR_T__SIZE_ERR);

/**
 * Return the packet header
 */
static inline odp_packet_hdr_t *odp_packet_hdr(odp_packet_t pkt)
{
	return (odp_packet_hdr_t *)odp_buf_to_hdr((odp_buffer_t)pkt);
}

/**
 * Parse packet and set internal metadata
 */
void odp_packet_parse(odp_packet_t pkt, size_t len, size_t l2_offset);

#ifdef __cplusplus
}
#endif

#endif

