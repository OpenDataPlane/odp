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

#include <odp_buffer_internal.h>
#include <odp_packet.h>
#include <odp_packet_io.h>


typedef struct odp_packet_hdr_t {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;

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


/**
 * Return the packet header
 */
static inline odp_packet_hdr_t *odp_packet_hdr(odp_packet_t pkt)
{
	return (odp_packet_hdr_t *)odp_buf_to_hdr((odp_buffer_t)pkt);
}


#ifdef __cplusplus
}
#endif

#endif

