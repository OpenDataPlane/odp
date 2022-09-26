/* Copyright (c) 2019-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_BUFFER_INLINES_H_
#define ODP_PLAT_BUFFER_INLINES_H_

#include <odp/api/event.h>
#include <odp/api/pool_types.h>

#include <odp/api/abi/buffer.h>

#include <odp/api/plat/debug_inlines.h>
#include <odp/api/plat/event_inline_types.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

extern const _odp_event_inline_offset_t _odp_event_inline_offset;

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_buffer_from_event __odp_buffer_from_event
	#define odp_buffer_to_event __odp_buffer_to_event
	#define odp_buffer_addr __odp_buffer_addr
	#define odp_buffer_pool __odp_buffer_pool
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE odp_buffer_t odp_buffer_from_event(odp_event_t ev)
{
	_ODP_ASSERT(odp_event_type(ev) == ODP_EVENT_BUFFER);

	return (odp_buffer_t)ev;
}

_ODP_INLINE odp_event_t odp_buffer_to_event(odp_buffer_t buf)
{
	return (odp_event_t)buf;
}

_ODP_INLINE void *odp_buffer_addr(odp_buffer_t buf)
{
	return _odp_event_hdr_field((odp_event_t)buf, void *, base_data);
}

_ODP_INLINE odp_pool_t odp_buffer_pool(odp_buffer_t buf)
{
	return _odp_event_hdr_field(buf, odp_pool_t, pool);
}

/** @endcond */

#endif
