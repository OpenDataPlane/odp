/* Copyright (c) 2020-2021, Nokia
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

#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp/api/packet.h>

#include <odp_event_internal.h>

#include <stdint.h>

/**
 * Internal event vector header
 */
typedef struct ODP_ALIGNED_CACHE odp_event_vector_hdr_t {
	/* Common event header */
	_odp_event_hdr_t event_hdr;

	/* User area pointer */
	void *uarea_addr;

	/* Event vector size */
	uint32_t size;

	/* Vector of packet handles */
	odp_packet_t packet[];

} odp_event_vector_hdr_t;

/* Vector header size is critical for performance. Ensure that it does not accidentally
 * grow over cache line size. */
ODP_STATIC_ASSERT(sizeof(odp_event_vector_hdr_t) <= ODP_CACHE_LINE_SIZE,
		  "EVENT_VECTOR_HDR_SIZE_ERROR");

/**
 * Return the vector header
 */
static inline odp_event_vector_hdr_t *_odp_packet_vector_hdr(odp_packet_vector_t pktv)
{
	return (odp_event_vector_hdr_t *)(uintptr_t)pktv;
}

/**
 * Free packet vector and contained packets
 */
static inline void _odp_packet_vector_free_full(odp_packet_vector_t pktv)
{
	odp_event_vector_hdr_t *pktv_hdr = _odp_packet_vector_hdr(pktv);

	if (pktv_hdr->size)
		odp_packet_free_multi(pktv_hdr->packet, pktv_hdr->size);

	odp_packet_vector_free(pktv);
}

#endif /* ODP_EVENT_VECTOR_INTERNAL_H_ */
