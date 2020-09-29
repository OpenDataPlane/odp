/* Copyright (c) 2020, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP event vector descriptor - implementation internal
 */

#ifndef ODP_EVENT_VECTOR_INTERNAL_H_
#define ODP_EVENT_VECTOR_INTERNAL_H_

#include <stdint.h>
#include <odp/api/packet.h>
#include <odp_buffer_internal.h>

/**
 * Internal event vector header
 */
typedef struct {
	/* Common buffer header */
	odp_buffer_hdr_t buf_hdr;

	/* Event vector size */
	uint32_t size;

	/* Vector of packet handles */
	odp_packet_t packet[0];

} odp_event_vector_hdr_t;

/**
 * Return the vector header
 */
static inline odp_event_vector_hdr_t *_odp_packet_vector_hdr(odp_packet_vector_t pktv)
{
	return (odp_event_vector_hdr_t *)(uintptr_t)pktv;
}

#endif /* ODP_EVENT_VECTOR_INTERNAL_H_ */
