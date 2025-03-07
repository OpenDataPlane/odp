/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2025 Nokia
 */

/**
 * @file
 *
 * Event vector inline functions
 */

#ifndef _ODP_PLAT_EVENT_VECTOR_INLINES_H_
#define _ODP_PLAT_EVENT_VECTOR_INLINES_H_

#include <odp/api/event.h>
#include <odp/api/packet_types.h>
#include <odp/api/pool_types.h>

#include <odp/api/plat/debug_inlines.h>
#include <odp/api/plat/event_vector_inline_types.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_event_vector_from_event __odp_event_vector_from_event
	#define odp_event_vector_to_event __odp_event_vector_to_event
	#define odp_event_vector_tbl __odp_event_vector_tbl
	#define odp_event_vector_pool __odp_event_vector_pool
	#define odp_event_vector_size __odp_event_vector_size
	#define odp_event_vector_size_set __odp_event_vector_size_set
	#define odp_event_vector_user_area __odp_event_vector_user_area
	#define odp_event_vector_user_flag __odp_event_vector_user_flag
	#define odp_event_vector_user_flag_set __odp_event_vector_user_flag_set
#else
	#undef _ODP_INLINE
	#define _ODP_INLINE
#endif

_ODP_INLINE odp_event_vector_t odp_event_vector_from_event(odp_event_t ev)
{
	_ODP_ASSERT(odp_event_type(ev) == ODP_EVENT_VECTOR);

	return (odp_event_vector_t)ev;
}

_ODP_INLINE odp_event_t odp_event_vector_to_event(odp_event_vector_t evv)
{
	return (odp_event_t)evv;
}

_ODP_INLINE uint32_t odp_event_vector_tbl(odp_event_vector_t evv, odp_event_t **ev_tbl)
{
	*ev_tbl = _odp_event_vect_get_ptr(evv, odp_event_t, event);

	return _odp_event_vect_get(evv, uint32_t, size);
}

_ODP_INLINE odp_pool_t odp_event_vector_pool(odp_event_vector_t evv)
{
	return _odp_event_vect_get(evv, odp_pool_t, pool);
}

_ODP_INLINE uint32_t odp_event_vector_size(odp_event_vector_t evv)
{
	return _odp_event_vect_get(evv, uint32_t, size);
}

_ODP_INLINE void odp_event_vector_size_set(odp_event_vector_t evv, uint32_t size)
{
	uint32_t *vector_size = _odp_event_vect_get_ptr(evv, uint32_t, size);

	*vector_size = size;
}

_ODP_INLINE void *odp_event_vector_user_area(odp_event_vector_t evv)
{
	return _odp_event_vect_get(evv, void *, uarea_addr);
}

_ODP_INLINE int odp_event_vector_user_flag(odp_event_vector_t evv)
{
	_odp_event_vector_flags_t flags;

	flags.all_flags = _odp_event_vect_get(evv, uint32_t, flags);

	return flags.user_flag;
}

_ODP_INLINE void odp_event_vector_user_flag_set(odp_event_vector_t evv, int val)
{
	_odp_event_vector_flags_t *flags = _odp_event_vect_get_ptr(evv, _odp_event_vector_flags_t,
								   flags);

	flags->user_flag = !!val;
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
