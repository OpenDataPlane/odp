/* Copyright (c) 2020, Nokia
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

#include <odp/api/abi/event.h>
#include <odp/api/abi/packet.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_packet_vector_from_event __odp_packet_vector_from_event
	#define odp_packet_vector_to_event __odp_packet_vector_to_event
#else
	#undef _ODP_INLINE
	#define _ODP_INLINE
#endif

_ODP_INLINE odp_packet_vector_t odp_packet_vector_from_event(odp_event_t ev)
{
	return (odp_packet_vector_t)ev;
}

_ODP_INLINE odp_event_t odp_packet_vector_to_event(odp_packet_vector_t pktv)
{
	return (odp_event_t)pktv;
}

/** @endcond */

#endif
