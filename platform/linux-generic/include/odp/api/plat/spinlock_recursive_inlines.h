/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_PLAT_SPINLOCK_RECURSIVE_INLINES_H_
#define ODP_PLAT_SPINLOCK_RECURSIVE_INLINES_H_

#include <odp/api/spinlock.h>
#include <odp/api/thread.h>

#include <odp/api/abi/spinlock_recursive.h>

#include <odp/api/plat/debug_inlines.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_spinlock_recursive_init __odp_spinlock_recursive_init
	#define odp_spinlock_recursive_lock __odp_spinlock_recursive_lock
	#define odp_spinlock_recursive_trylock __odp_spinlock_recursive_trylock
	#define odp_spinlock_recursive_unlock __odp_spinlock_recursive_unlock
	#define odp_spinlock_recursive_is_locked __odp_spinlock_recursive_is_locked
#else
	#undef _ODP_INLINE
	#define _ODP_INLINE
#endif

_ODP_INLINE void odp_spinlock_recursive_init(odp_spinlock_recursive_t *rlock)
{
	odp_spinlock_init(&rlock->lock);
	rlock->owner = -1;
	rlock->cnt   = 0;
}

_ODP_INLINE void odp_spinlock_recursive_lock(odp_spinlock_recursive_t *rlock)
{
	int thr = odp_thread_id();

	if (rlock->owner == thr) {
		_ODP_ASSERT(rlock->cnt < UINT32_MAX);
		rlock->cnt++;
		return;
	}

	odp_spinlock_lock(&rlock->lock);
	rlock->owner = thr;
	rlock->cnt   = 1;
}

_ODP_INLINE int odp_spinlock_recursive_trylock(odp_spinlock_recursive_t *rlock)
{
	int thr = odp_thread_id();

	if (rlock->owner == thr) {
		_ODP_ASSERT(rlock->cnt < UINT32_MAX);
		rlock->cnt++;
		return 1;
	}

	if (odp_spinlock_trylock(&rlock->lock)) {
		rlock->owner = thr;
		rlock->cnt   = 1;
		return 1;
	}

	return 0;
}

_ODP_INLINE void odp_spinlock_recursive_unlock(odp_spinlock_recursive_t *rlock)
{
	_ODP_ASSERT(rlock->cnt);
	rlock->cnt--;

	if (rlock->cnt > 0)
		return;

	rlock->owner = -1;
	odp_spinlock_unlock(&rlock->lock);
}

_ODP_INLINE int odp_spinlock_recursive_is_locked(odp_spinlock_recursive_t *rlock)
{
	return odp_thread_id() == rlock->owner ? 1 : odp_spinlock_is_locked(&rlock->lock);
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
