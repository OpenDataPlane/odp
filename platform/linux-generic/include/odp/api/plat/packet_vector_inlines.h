/* Copyright (c) 2020-2022, Nokia
 *
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * Packet vector inline functions
 */

#ifndef _ODP_PLAT_PACKET_VECTOR_INLINES_H_
#define _ODP_PLAT_PACKET_VECTOR_INLINES_H_

#include <odp/api/event_types.h>
#include <odp/api/packet_types.h>
#include <odp/api/pool_types.h>

#include <odp/api/plat/event_vector_inline_types.h>

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_packet_vector_from_event __odp_packet_vector_from_event
	#define odp_packet_vector_to_event __odp_packet_vector_to_event
	#define odp_packet_vector_tbl __odp_packet_vector_tbl
	#define odp_packet_vector_pool __odp_packet_vector_pool
	#define odp_packet_vector_size __odp_packet_vector_size
	#define odp_packet_vector_size_set __odp_packet_vector_size_set
	#define odp_packet_vector_user_area __odp_packet_vector_user_area
#else
	#undef _ODP_INLINE
	#define _ODP_INLINE
#endif

extern const _odp_event_vector_inline_offset_t _odp_event_vector_inline;

_ODP_INLINE odp_packet_vector_t odp_packet_vector_from_event(odp_event_t ev)
{
	return (odp_packet_vector_t)ev;
}

_ODP_INLINE odp_event_t odp_packet_vector_to_event(odp_packet_vector_t pktv)
{
	return (odp_event_t)pktv;
}

_ODP_INLINE uint32_t odp_packet_vector_tbl(odp_packet_vector_t pktv, odp_packet_t **pkt_tbl)
{
	*pkt_tbl = _odp_event_vect_get_ptr(pktv, odp_packet_t, packet);

	return _odp_event_vect_get(pktv, uint32_t, size);
}

_ODP_INLINE odp_pool_t odp_packet_vector_pool(odp_packet_vector_t pktv)
{
	return _odp_event_vect_get(pktv, odp_pool_t, pool);
}

_ODP_INLINE uint32_t odp_packet_vector_size(odp_packet_vector_t pktv)
{
	return _odp_event_vect_get(pktv, uint32_t, size);
}

_ODP_INLINE void odp_packet_vector_size_set(odp_packet_vector_t pktv, uint32_t size)
{
	uint32_t *vector_size = _odp_event_vect_get_ptr(pktv, uint32_t, size);

	*vector_size = size;
}

_ODP_INLINE void *odp_packet_vector_user_area(odp_packet_vector_t pktv)
{
	return _odp_event_vect_get(pktv, void *, uarea_addr);
}

/** @endcond */

#endif
