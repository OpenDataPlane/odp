/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2025 Nokia
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
#include <odp/api/buffer.h>
#include <odp/api/event_vector.h>

#include <odp/api/plat/event_vector_inline_types.h>

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

	/* Common type of the events in the vector or ODP_EVENT_ANY */
	odp_event_type_t event_type;

	/* Flags */
	_odp_event_vector_flags_t flags;

	/* Vector of event handles */
	odp_event_t event[];

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
 * Return the vector header
 */
static inline odp_event_vector_hdr_t *_odp_event_vector_hdr(odp_event_vector_t evv)
{
	return (odp_event_vector_hdr_t *)(uintptr_t)evv;
}

/**
 * Return the event header
 */
static inline _odp_event_hdr_t *_odp_packet_vector_to_event_hdr(odp_packet_vector_t pktv)
{
	return &_odp_packet_vector_hdr(pktv)->event_hdr;
}

/**
 * Return the event header
 */
static inline _odp_event_hdr_t *_odp_event_vector_to_event_hdr(odp_event_vector_t evv)
{
	return &_odp_event_vector_hdr(evv)->event_hdr;
}

/**
 * Free packet vector and contained packets
 */
static inline void _odp_packet_vector_free_full(odp_packet_vector_t pktv)
{
	odp_event_vector_hdr_t *pktv_hdr = _odp_packet_vector_hdr(pktv);

	if (pktv_hdr->size)
		odp_packet_free_multi((odp_packet_t *)pktv_hdr->event, pktv_hdr->size);

	odp_packet_vector_free(pktv);
}

/**
 * Free event vector and contained events
 */
static inline void _odp_event_vector_free_full(odp_event_vector_t evv)
{
	odp_event_vector_hdr_t *evv_hdr = _odp_event_vector_hdr(evv);

	for (uint32_t i = 0; i < evv_hdr->size; i++) {
		_ODP_ASSERT(odp_event_type(evv_hdr->event[i]) != ODP_EVENT_VECTOR &&
			    odp_event_type(evv_hdr->event[i]) != ODP_EVENT_PACKET_VECTOR);
		_ODP_ASSERT(evv_hdr->event_type == ODP_EVENT_ANY ||
			    evv_hdr->event_type == odp_event_type(evv_hdr->event[i]));
	}

	if (evv_hdr->size > 0) {
		if (evv_hdr->event_type == ODP_EVENT_PACKET)
			odp_packet_free_multi((odp_packet_t *)evv_hdr->event, evv_hdr->size);
		else if (evv_hdr->event_type == ODP_EVENT_BUFFER)
			odp_buffer_free_multi((odp_buffer_t *)evv_hdr->event, evv_hdr->size);
		else
			odp_event_free_multi(evv_hdr->event, evv_hdr->size);
	}
	odp_event_vector_free(evv);
}

#endif /* ODP_EVENT_VECTOR_INTERNAL_H_ */
