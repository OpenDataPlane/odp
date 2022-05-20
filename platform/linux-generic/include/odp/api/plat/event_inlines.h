/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_EVENT_INLINES_H_
#define ODP_PLAT_EVENT_INLINES_H_

#include <odp/api/event_types.h>

#include <odp/api/plat/event_inline_types.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

extern const _odp_event_inline_offset_t _odp_event_inline_offset;

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_event_type __odp_event_type
	#define odp_event_type_multi __odp_event_type_multi
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

/** @endcond */

#endif
