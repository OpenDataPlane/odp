/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_EVENT_INLINES_H_
#define ODP_PLAT_EVENT_INLINES_H_

#include <odp/api/event_types.h>
#include <odp/api/packet.h>

#include <odp/api/plat/event_inline_types.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

extern const _odp_event_inline_offset_t _odp_event_inline_offset;

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_event_type __odp_event_type
	#define odp_event_type_multi __odp_event_type_multi
	#define odp_event_subtype __odp_event_subtype
	#define odp_event_types __odp_event_types
	#define odp_event_flow_id __odp_event_flow_id
	#define odp_event_flow_id_set __odp_event_flow_id_set

	#include <odp/api/plat/packet_inlines.h>
#else
	#define _ODP_INLINE
#endif

static inline odp_event_type_t __odp_event_type_get(odp_event_t event)
{
	int8_t type;

	type = _odp_event_hdr_field(event, int8_t, event_type);

	return (odp_event_type_t)type;
}

_ODP_INLINE odp_event_type_t odp_event_type(odp_event_t event)
{
	return __odp_event_type_get(event);
}

_ODP_INLINE int odp_event_type_multi(const odp_event_t event[], int num,
				     odp_event_type_t *type_out)
{
	int i;
	odp_event_type_t type = __odp_event_type_get(event[0]);

	for (i = 1; i < num; i++) {
		if (__odp_event_type_get(event[i]) != type)
			break;
	}

	*type_out = type;

	return i;
}

_ODP_INLINE odp_event_subtype_t odp_event_subtype(odp_event_t event)
{
	if (__odp_event_type_get(event) != ODP_EVENT_PACKET)
		return ODP_EVENT_NO_SUBTYPE;

	return odp_packet_subtype(odp_packet_from_event(event));
}

_ODP_INLINE odp_event_type_t odp_event_types(odp_event_t event,
					     odp_event_subtype_t *subtype)
{
	odp_event_type_t event_type = __odp_event_type_get(event);

	*subtype = event_type == ODP_EVENT_PACKET ?
			odp_packet_subtype(odp_packet_from_event(event)) :
			ODP_EVENT_NO_SUBTYPE;

	return event_type;
}

_ODP_INLINE uint32_t odp_event_flow_id(odp_event_t event)
{
	return _odp_event_hdr_field(event, uint8_t, flow_id);
}

_ODP_INLINE void odp_event_flow_id_set(odp_event_t event, uint32_t id)
{
	uint8_t *flow_id = _odp_event_hdr_ptr(event, uint8_t, flow_id);

	*flow_id = (uint8_t)id;
}

/** @endcond */

#endif
