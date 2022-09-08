/* Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_TIMER_INLINES_H_
#define ODP_PLAT_TIMER_INLINES_H_

#include <odp/api/event.h>
#include <odp/api/timer_types.h>

#include <odp/api/plat/timer_inline_types.h>

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

extern const _odp_timeout_inline_offset_t _odp_timeout_inline_offset;

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_timeout_timer __odp_timeout_timer
	#define odp_timeout_tick __odp_timeout_tick
	#define odp_timeout_user_ptr __odp_timeout_user_ptr
	#define odp_timeout_user_area __odp_timeout_user_area
	#define odp_timer_tick_to_ns __odp_timer_tick_to_ns
	#define odp_timer_ns_to_tick __odp_timer_ns_to_tick
	#define odp_timeout_from_event __odp_timeout_from_event
	#define odp_timeout_to_event __odp_timeout_to_event
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE odp_timer_t odp_timeout_timer(odp_timeout_t tmo)
{
	return _odp_timeout_hdr_field(tmo, odp_timer_t, timer);
}

_ODP_INLINE uint64_t odp_timeout_tick(odp_timeout_t tmo)
{
	return _odp_timeout_hdr_field(tmo, uint64_t, expiration);
}

_ODP_INLINE void *odp_timeout_user_ptr(odp_timeout_t tmo)
{
	return _odp_timeout_hdr_field(tmo, void *, user_ptr);
}

_ODP_INLINE void *odp_timeout_user_area(odp_timeout_t tmo)
{
	return _odp_timeout_hdr_field(tmo, void *, uarea_addr);
}

_ODP_INLINE uint64_t odp_timer_tick_to_ns(odp_timer_pool_t tp, uint64_t ticks)
{
	(void)tp;

	/* Timer ticks in API are nsec */
	return ticks;
}

_ODP_INLINE uint64_t odp_timer_ns_to_tick(odp_timer_pool_t tp, uint64_t ns)
{
	(void)tp;

	/* Timer ticks in API are nsec */
	return ns;
}

_ODP_INLINE odp_timeout_t odp_timeout_from_event(odp_event_t ev)
{
	return (odp_timeout_t)ev;
}

_ODP_INLINE odp_event_t odp_timeout_to_event(odp_timeout_t tmo)
{
	return (odp_event_t)tmo;
}

/** @endcond */

#endif
