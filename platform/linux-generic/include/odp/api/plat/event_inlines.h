/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_EVENT_INLINES_H_
#define ODP_PLAT_EVENT_INLINES_H_

#include <odp/api/abi/buffer.h>
#include <odp/api/plat/buffer_inline_types.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

extern const _odp_buffer_inline_offset_t _odp_buffer_inline_offset;

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_event_type __odp_event_type
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE odp_event_type_t odp_event_type(odp_event_t event)
{
	int8_t type;
	odp_buffer_t buf = (odp_buffer_t)event;

	type = _odp_buf_hdr_field(buf, int8_t, event_type);

	return (odp_event_type_t)type;
}

/** @endcond */

#endif
