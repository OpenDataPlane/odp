/* Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_IPSEC_INLINES_H_
#define ODP_PLAT_IPSEC_INLINES_H_

#include <odp/api/event.h>
#include <odp/api/packet.h>

#include <odp/api/plat/debug_inlines.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_ipsec_packet_from_event __odp_ipsec_packet_from_event
	#define odp_ipsec_packet_to_event __odp_ipsec_packet_to_event
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE odp_packet_t odp_ipsec_packet_from_event(odp_event_t ev)
{
	_ODP_ASSERT(odp_event_type(ev) == ODP_EVENT_PACKET);
	_ODP_ASSERT(odp_event_subtype(ev) == ODP_EVENT_PACKET_IPSEC);

	return odp_packet_from_event(ev);
}

_ODP_INLINE odp_event_t odp_ipsec_packet_to_event(odp_packet_t pkt)
{
	return odp_packet_to_event(pkt);
}

/** @endcond */

#endif
