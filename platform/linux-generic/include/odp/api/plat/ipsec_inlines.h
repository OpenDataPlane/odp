/* Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_IPSEC_INLINES_H_
#define ODP_PLAT_IPSEC_INLINES_H_

#include <odp/api/event.h>
#include <odp/api/ipsec_types.h>
#include <odp/api/packet.h>

#include <odp/api/plat/debug_inlines.h>
#include <odp/api/plat/packet_inline_types.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_ipsec_packet_from_event __odp_ipsec_packet_from_event
	#define odp_ipsec_packet_to_event __odp_ipsec_packet_to_event
	#define odp_ipsec_result __odp_ipsec_result
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

_ODP_INLINE int odp_ipsec_result(odp_ipsec_packet_result_t *result, odp_packet_t pkt)
{
	odp_ipsec_packet_result_t *res;

	_ODP_ASSERT(result != NULL);
	_ODP_ASSERT(odp_packet_subtype(pkt) == ODP_EVENT_PACKET_IPSEC);

	res = _odp_pkt_get_ptr(pkt, odp_ipsec_packet_result_t, ipsec_ctx);

	*result = *res;

	return 0;
}

/** @endcond */

#endif
