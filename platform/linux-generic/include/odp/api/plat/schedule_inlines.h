/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_PLAT_SCHEDULE_INLINES_H_
#define ODP_PLAT_SCHEDULE_INLINES_H_

#include <odp/api/event_types.h>
#include <odp/api/queue_types.h>

#include <odp/api/plat/debug_inlines.h>
#include <odp/api/plat/schedule_inline_types.h>

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

extern const _odp_schedule_api_fn_t *_odp_sched_api;

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_schedule __odp_schedule
	#define odp_schedule_multi __odp_schedule_multi
	#define odp_schedule_multi_wait __odp_schedule_multi_wait
	#define odp_schedule_multi_no_wait __odp_schedule_multi_no_wait
	#define odp_schedule_wait_time __odp_schedule_wait_time
	#define odp_schedule_pause __odp_schedule_pause
	#define odp_schedule_resume __odp_schedule_resume
	#define odp_schedule_release_atomic __odp_schedule_release_atomic
	#define odp_schedule_release_ordered __odp_schedule_release_ordered
	#define odp_schedule_prefetch __odp_schedule_prefetch
	#define odp_schedule_order_lock __odp_schedule_order_lock
	#define odp_schedule_order_unlock __odp_schedule_order_unlock
	#define odp_schedule_order_unlock_lock __odp_schedule_order_unlock_lock
	#define odp_schedule_order_lock_start __odp_schedule_order_lock_start
	#define odp_schedule_order_lock_wait __odp_schedule_order_lock_wait
	#define odp_schedule_order_wait __odp_schedule_order_wait
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE odp_event_t odp_schedule(odp_queue_t *from, uint64_t wait)
{
	_ODP_ASSERT(_odp_schedule_configured());

	return _odp_sched_api->schedule(from, wait);
}

_ODP_INLINE int odp_schedule_multi(odp_queue_t *from, uint64_t wait, odp_event_t events[], int num)
{
	_ODP_ASSERT(_odp_schedule_configured());

	return _odp_sched_api->schedule_multi(from, wait, events, num);
}

_ODP_INLINE int odp_schedule_multi_wait(odp_queue_t *from, odp_event_t events[], int num)
{
	_ODP_ASSERT(_odp_schedule_configured());

	return _odp_sched_api->schedule_multi_wait(from, events, num);
}

_ODP_INLINE int odp_schedule_multi_no_wait(odp_queue_t *from, odp_event_t events[], int num)
{
	_ODP_ASSERT(_odp_schedule_configured());

	return _odp_sched_api->schedule_multi_no_wait(from, events, num);
}

_ODP_INLINE uint64_t odp_schedule_wait_time(uint64_t ns)
{
	return _odp_sched_api->schedule_wait_time(ns);
}

_ODP_INLINE void odp_schedule_pause(void)
{
	_odp_sched_api->schedule_pause();
}

_ODP_INLINE void odp_schedule_resume(void)
{
	_odp_sched_api->schedule_resume();
}

_ODP_INLINE void odp_schedule_release_atomic(void)
{
	_odp_sched_api->schedule_release_atomic();
}

_ODP_INLINE void odp_schedule_release_ordered(void)
{
	_odp_sched_api->schedule_release_ordered();
}

_ODP_INLINE void odp_schedule_prefetch(int num)
{
	_odp_sched_api->schedule_prefetch(num);
}

_ODP_INLINE void odp_schedule_order_lock(uint32_t lock_index)
{
	_odp_sched_api->schedule_order_lock(lock_index);
}

_ODP_INLINE void odp_schedule_order_unlock(uint32_t lock_index)
{
	_odp_sched_api->schedule_order_unlock(lock_index);
}

_ODP_INLINE void odp_schedule_order_unlock_lock(uint32_t unlock_index, uint32_t lock_index)
{
	_odp_sched_api->schedule_order_unlock_lock(unlock_index, lock_index);
}

_ODP_INLINE void odp_schedule_order_lock_start(uint32_t lock_index)
{
	_odp_sched_api->schedule_order_lock_start(lock_index);
}

_ODP_INLINE void odp_schedule_order_lock_wait(uint32_t lock_index)
{
	_odp_sched_api->schedule_order_lock_wait(lock_index);
}

_ODP_INLINE void odp_schedule_order_wait(void)
{
	_odp_sched_api->schedule_order_wait();
}

/** @endcond */

#endif
